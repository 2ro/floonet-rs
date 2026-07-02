//! Event admission: composable write-side policies (Floonet addition).
//!
//! Every EVENT a client publishes passes through one `Admission::check`
//! call in the websocket write path, before the event is queued for the
//! database writer. The admission layer is a fixed, ordered list of small
//! policies; the first policy that denies wins. To add a new policy
//! (paid gate, name-authority check, spam filter), implement
//! [`AdmissionPolicy`] and append it in [`Admission::from_settings`].
//!
//! The keystone policy is the default-deny kind whitelist: the relay
//! accepts ONLY the event kinds it was explicitly configured to allow and
//! rejects everything else. If no allowlist is configured at all, the
//! built-in Floonet set applies (fail closed, never fail open).

use crate::config::Settings;
use crate::event::Event;

/// The Floonet default kind whitelist, applied when the operator has not
/// configured `event_kind_allowlist` explicitly. Kinds:
/// 0 profile metadata, 3 contacts, 5 delete (NIP-09), 13 seal,
/// 1059 gift wrap (NIP-59), 10002 relay list (NIP-65),
/// 10050 DM relays (NIP-17), 27235 NIP-98 HTTP auth.
pub const DEFAULT_ALLOWED_KINDS: [u64; 8] = [0, 3, 5, 13, 1059, 10002, 10050, 27235];

/// Outcome of an admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Event may proceed to the write path.
    Allow,
    /// Event is rejected before persistence.
    Deny {
        /// Human-readable reason, sent to the client in the OK message.
        reason: String,
        /// True when the denial is because the client has not completed
        /// NIP-42 AUTH; the client should be told with an
        /// `auth-required:` prefixed OK message.
        auth_required: bool,
    },
}

impl Decision {
    fn deny(reason: &str) -> Decision {
        Decision::Deny {
            reason: reason.to_string(),
            auth_required: false,
        }
    }

    fn deny_auth(reason: &str) -> Decision {
        Decision::Deny {
            reason: reason.to_string(),
            auth_required: true,
        }
    }
}

/// One admission policy. `authed_pubkey` is the NIP-42 authenticated pubkey
/// for this connection, if any.
pub trait AdmissionPolicy: Send + Sync {
    fn check(&self, event: &Event, authed_pubkey: Option<&str>) -> Decision;
}

/// Default-deny event kind whitelist (the keystone).
pub struct KindWhitelist {
    allowed: Vec<u64>,
}

impl AdmissionPolicy for KindWhitelist {
    fn check(&self, event: &Event, _authed_pubkey: Option<&str>) -> Decision {
        if self.allowed.contains(&event.kind) {
            Decision::Allow
        } else {
            Decision::deny(&format!(
                "event kind {} not accepted by this relay",
                event.kind
            ))
        }
    }
}

/// Require a completed NIP-42 AUTH before any event is accepted.
pub struct RequireAuth;

impl AdmissionPolicy for RequireAuth {
    fn check(&self, _event: &Event, authed_pubkey: Option<&str>) -> Decision {
        if authed_pubkey.is_some() {
            Decision::Allow
        } else {
            Decision::deny_auth("authentication required to publish events")
        }
    }
}

/// Restrict publishing to a fixed set of author pubkeys. Matches the
/// upstream semantics: when pay-to-relay is enabled the whitelist means
/// "posts for free" and is handled by the payment layer instead, so this
/// policy is only installed when pay-to-relay is off.
pub struct PubkeyWhitelist {
    allowed: Vec<String>,
}

impl AdmissionPolicy for PubkeyWhitelist {
    fn check(&self, event: &Event, _authed_pubkey: Option<&str>) -> Decision {
        if self.allowed.contains(&event.pubkey) {
            Decision::Allow
        } else {
            Decision::deny("pubkey is not allowed to publish to this relay")
        }
    }
}

/// The composed admission pipeline the server consults.
pub struct Admission {
    policies: Vec<Box<dyn AdmissionPolicy>>,
}

impl Admission {
    /// Build the policy pipeline from settings. Order matters: the kind
    /// whitelist runs first (cheapest, and the keystone), then auth, then
    /// author restrictions.
    pub fn from_settings(settings: &Settings) -> Admission {
        let mut policies: Vec<Box<dyn AdmissionPolicy>> = Vec::new();
        // Keystone: default-deny kind whitelist. A missing allowlist gets
        // the built-in Floonet set; an explicitly empty list denies all.
        let allowed = settings
            .limits
            .event_kind_allowlist
            .clone()
            .unwrap_or_else(|| DEFAULT_ALLOWED_KINDS.to_vec());
        policies.push(Box::new(KindWhitelist { allowed }));
        // Optional: require NIP-42 auth to write.
        if settings.authorization.nip42_auth && settings.authorization.require_auth_to_write {
            policies.push(Box::new(RequireAuth));
        }
        // Optional: author whitelist (free relays only; paid relays treat
        // the whitelist as a fee exemption in the payment layer).
        if !settings.pay_to_relay.enabled {
            if let Some(whitelist) = &settings.authorization.pubkey_whitelist {
                policies.push(Box::new(PubkeyWhitelist {
                    allowed: whitelist.clone(),
                }));
            }
        }
        Admission { policies }
    }

    /// Check an event against every policy in order; first denial wins.
    pub fn check(&self, event: &Event, authed_pubkey: Option<&str>) -> Decision {
        for policy in &self.policies {
            match policy.check(event, authed_pubkey) {
                Decision::Allow => continue,
                deny => return deny,
            }
        }
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_of_kind(kind: u64) -> Event {
        let mut e = Event::simple_event();
        e.kind = kind;
        e
    }

    fn floonet_settings() -> Settings {
        // The shipped defaults already carry the Floonet whitelist.
        Settings::default()
    }

    #[test]
    fn default_whitelist_accepts_allowed_kinds() {
        let admission = Admission::from_settings(&floonet_settings());
        for kind in DEFAULT_ALLOWED_KINDS {
            assert_eq!(
                admission.check(&event_of_kind(kind), None),
                Decision::Allow,
                "kind {kind} should be allowed"
            );
        }
    }

    #[test]
    fn default_whitelist_rejects_disallowed_kinds() {
        let admission = Admission::from_settings(&floonet_settings());
        // kind 1 (short text note) and other common kinds are NOT accepted.
        for kind in [1u64, 4, 6, 7, 42, 1984, 9735, 30023] {
            match admission.check(&event_of_kind(kind), None) {
                Decision::Deny { auth_required, .. } => {
                    assert!(!auth_required, "kind rejection is not an auth issue");
                }
                Decision::Allow => panic!("kind {kind} must be rejected by default"),
            }
        }
    }

    #[test]
    fn missing_allowlist_falls_back_to_floonet_set_not_allow_all() {
        let mut settings = floonet_settings();
        settings.limits.event_kind_allowlist = None;
        let admission = Admission::from_settings(&settings);
        assert_eq!(admission.check(&event_of_kind(1059), None), Decision::Allow);
        assert_ne!(admission.check(&event_of_kind(1), None), Decision::Allow);
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let mut settings = floonet_settings();
        settings.limits.event_kind_allowlist = Some(vec![]);
        let admission = Admission::from_settings(&settings);
        assert_ne!(admission.check(&event_of_kind(0), None), Decision::Allow);
        assert_ne!(admission.check(&event_of_kind(1059), None), Decision::Allow);
    }

    #[test]
    fn custom_allowlist_is_respected() {
        let mut settings = floonet_settings();
        settings.limits.event_kind_allowlist = Some(vec![1, 7]);
        let admission = Admission::from_settings(&settings);
        assert_eq!(admission.check(&event_of_kind(1), None), Decision::Allow);
        assert_ne!(admission.check(&event_of_kind(0), None), Decision::Allow);
    }

    #[test]
    fn require_auth_denies_unauthed_writes_with_auth_required() {
        let mut settings = floonet_settings();
        settings.authorization.nip42_auth = true;
        settings.authorization.require_auth_to_write = true;
        let admission = Admission::from_settings(&settings);
        match admission.check(&event_of_kind(1059), None) {
            Decision::Deny { auth_required, .. } => assert!(auth_required),
            Decision::Allow => panic!("unauthenticated write must be denied"),
        }
        // After AUTH, the same event is accepted.
        let pk = "aa".repeat(32);
        assert_eq!(
            admission.check(&event_of_kind(1059), Some(pk.as_str())),
            Decision::Allow
        );
    }

    #[test]
    fn require_auth_without_nip42_is_inert() {
        // require_auth_to_write only makes sense with nip42_auth on; the
        // relay never sends a challenge otherwise, so the gate is skipped.
        let mut settings = floonet_settings();
        settings.authorization.nip42_auth = false;
        settings.authorization.require_auth_to_write = true;
        let admission = Admission::from_settings(&settings);
        assert_eq!(admission.check(&event_of_kind(1059), None), Decision::Allow);
    }

    #[test]
    fn pubkey_whitelist_enforced_when_free() {
        let mut settings = floonet_settings();
        let good = "aa".repeat(32);
        settings.authorization.pubkey_whitelist = Some(vec![good.clone()]);
        let admission = Admission::from_settings(&settings);
        let mut e = event_of_kind(0);
        e.pubkey = good;
        assert_eq!(admission.check(&e, None), Decision::Allow);
        e.pubkey = "bb".repeat(32);
        assert_ne!(admission.check(&e, None), Decision::Allow);
    }

    #[test]
    fn kind_check_runs_before_auth_check() {
        let mut settings = floonet_settings();
        settings.authorization.nip42_auth = true;
        settings.authorization.require_auth_to_write = true;
        let admission = Admission::from_settings(&settings);
        match admission.check(&event_of_kind(1), None) {
            Decision::Deny { auth_required, .. } => {
                assert!(!auth_required, "disallowed kind must not leak auth hints");
            }
            Decision::Allow => panic!("must deny"),
        }
    }
}
