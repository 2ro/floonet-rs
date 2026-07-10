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
/// configured `event_kind_allowlist` explicitly. It is the union of the two
/// apps this relay serves (default-deny for everything else).
///
/// Goblin wallet: 0 profile, 3 contacts, 5 delete (NIP-09), 13 seal (NIP-59),
/// 1059 gift wrap (NIP-59), 10002 relay list (NIP-65), 10050 DM relays
/// (NIP-17), 24133 remote signing (NIP-46), 24140 Authorize Sessions channel
/// (Goblin-native), 27235 NIP-98 HTTP auth (name authority).
///
/// Magick Market: 1 text note, 7 reaction (NIP-25), 14 order chat, 16 order
/// status, 17 payment receipt (Gamma), 1111 comment (NIP-22), 10000
/// mute/blacklist, 30000 people set, 30003 bookmark set (NIP-51), 30078 app
/// data (NIP-78), 30402 product listing (NIP-99), 30405 product collection,
/// 30406 shipping option (Gamma), 31990 handler info (NIP-89).
pub const DEFAULT_ALLOWED_KINDS: [u64; 25] = [
    0, 1, 3, 5, 7, 13, 14, 16, 17, 1059, 1111, 10000, 10002, 10050, 24133, 24140, 27235, 30000,
    30003, 30023, 30078, 30402, 30405, 30406, 31990,
];

/// The public-note kinds accepted only from authorized authors: 1 (text
/// note) and 30023 (long-form article). See [`RestrictedKindAuthors`].
pub const LOCKED_KINDS: [u64; 2] = [1, 30023];

/// The gift-wrap kind (NIP-59) carrying Grin payment envelopes. See
/// [`GiftWrapRetention`].
const GIFT_WRAP_KIND: u64 = 1059;

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

/// Restrict the public-note kinds (1 text note, 30023 long-form article) to
/// an operator-configured set of authorized author pubkeys. Closed by
/// default: with no authors configured these kinds are rejected for everyone,
/// so random notes cannot be spammed to the relay. Every other kind (0
/// profiles, 1059 gift wraps, marketplace kinds, lists, ephemeral) is
/// completely unaffected. Always installed, so the lockdown holds even when
/// the operator left the author list unset.
pub struct RestrictedKindAuthors {
    /// Canonical lowercase-hex author pubkeys allowed to publish locked kinds.
    authors: Vec<String>,
}

impl RestrictedKindAuthors {
    /// Build from operator config entries, each an npub or a 32-byte hex
    /// pubkey (operator's choice). Invalid entries are logged and skipped
    /// rather than failing the whole relay.
    fn from_entries(entries: &[String]) -> RestrictedKindAuthors {
        let mut authors = Vec::new();
        for entry in entries {
            let e = entry.trim();
            if e.is_empty() {
                continue;
            }
            let hex = if crate::utils::is_nip19(e) {
                crate::utils::nip19_to_hex(e).ok()
            } else if e.len() == 64 && crate::utils::is_hex(e) {
                Some(e.to_lowercase())
            } else {
                None
            };
            match hex {
                Some(h) if h.len() == 64 => authors.push(h.to_lowercase()),
                _ => tracing::warn!("ignoring invalid public_note_authors entry: {:?}", entry),
            }
        }
        RestrictedKindAuthors { authors }
    }
}

impl AdmissionPolicy for RestrictedKindAuthors {
    fn check(&self, event: &Event, _authed_pubkey: Option<&str>) -> Decision {
        if !LOCKED_KINDS.contains(&event.kind) {
            return Decision::Allow;
        }
        if self.authors.contains(&event.pubkey.to_lowercase()) {
            Decision::Allow
        } else {
            Decision::deny("this relay accepts public notes only from authorized authors")
        }
    }
}

/// Gift-wrap retention/shape guard (kind 1059 only). Parity with
/// floonet-strfry's write-policy plugin (commit 55231da): this relay's
/// database writer honors NIP-40 `expiration` tags as an automatic deletion
/// trigger, so a Grin payment gift wrap must never carry one. Also requires
/// exactly one well-formed `p` tag (32-byte hex recipient) so a malformed
/// gift wrap the recipient's client cannot route never lands on the relay
/// either. Every other kind is unaffected. Fails closed on malformed tags,
/// matching every other policy here.
pub struct GiftWrapRetention;

impl AdmissionPolicy for GiftWrapRetention {
    fn check(&self, event: &Event, _authed_pubkey: Option<&str>) -> Decision {
        if event.kind != GIFT_WRAP_KIND {
            return Decision::Allow;
        }
        if event
            .tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("expiration"))
        {
            return Decision::deny("expiration not allowed on gift wraps");
        }
        let p_pubkeys: Vec<&str> = event
            .tags
            .iter()
            .filter(|tag| tag.len() >= 2 && tag[0] == "p")
            .map(|tag| tag[1].as_str())
            .collect();
        let recipient_ok = match p_pubkeys.as_slice() {
            [pubkey] => pubkey.len() == 64 && crate::utils::is_hex(pubkey),
            _ => false,
        };
        if !recipient_ok {
            return Decision::deny("gift wrap missing recipient");
        }
        Decision::Allow
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
        // Gift-wrap retention/shape guard: kind 1059 only, no expiration
        // tag, exactly one well-formed p recipient. Always installed right
        // after the kind whitelist so only already-allowed 1059s are
        // inspected, before any auth or author-restriction policy runs.
        policies.push(Box::new(GiftWrapRetention));
        // Public-note lockdown: kinds 1 and 30023 only from authorized
        // authors. Always installed (closed by default) and placed right
        // after the kind whitelist so a locked kind is decided before auth.
        let public_note_authors = settings
            .authorization
            .public_note_authors
            .as_deref()
            .unwrap_or(&[]);
        policies.push(Box::new(RestrictedKindAuthors::from_entries(
            public_note_authors,
        )));
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

    /// Kind 1059 (gift wrap) defaults to a single well-formed `p` tag so
    /// existing tests that only care about other checks keep passing the
    /// gift-wrap retention/shape guard; the guard's own tests below build
    /// tags explicitly to exercise it directly.
    fn event_of_kind(kind: u64) -> Event {
        let mut e = Event::simple_event();
        e.kind = kind;
        if kind == GIFT_WRAP_KIND {
            e.tags = vec![tag(&["p", &"aa".repeat(32)])];
        }
        e
    }

    fn tag(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    fn floonet_settings() -> Settings {
        // The shipped defaults already carry the Floonet whitelist.
        Settings::default()
    }

    #[test]
    fn default_whitelist_accepts_allowed_kinds() {
        // Authorize a known author so the locked public-note kinds (1, 30023)
        // also pass; this test only exercises the kind whitelist.
        let author = "aa".repeat(32);
        let mut settings = floonet_settings();
        settings.authorization.public_note_authors = Some(vec![author.clone()]);
        let admission = Admission::from_settings(&settings);
        for kind in DEFAULT_ALLOWED_KINDS {
            let mut e = event_of_kind(kind);
            e.pubkey = author.clone();
            assert_eq!(
                admission.check(&e, None),
                Decision::Allow,
                "kind {kind} should be allowed"
            );
        }
    }

    #[test]
    fn default_whitelist_rejects_disallowed_kinds() {
        let admission = Admission::from_settings(&floonet_settings());
        // Common kinds outside the two-app whitelist are NOT accepted.
        // (30023 is now whitelisted but author-locked; see the lockdown tests.)
        for kind in [4u64, 6, 42, 1984, 9735, 25910, 30017, 30018] {
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
        // 9735 is not in the Floonet set, so a missing allowlist must reject
        // it (proving the fallback is the set, not allow-all).
        assert_ne!(admission.check(&event_of_kind(9735), None), Decision::Allow);
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
        // Kind 7 is in the custom list and is not author-locked.
        assert_eq!(admission.check(&event_of_kind(7), None), Decision::Allow);
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
        match admission.check(&event_of_kind(30023), None) {
            Decision::Deny { auth_required, .. } => {
                assert!(!auth_required, "locked kind must not leak auth hints");
            }
            Decision::Allow => panic!("must deny"),
        }
    }

    // --- Public-note lockdown (kinds 1, 30023) ---

    const AUTH_HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const AUTH_NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    fn event_from(kind: u64, pubkey: &str) -> Event {
        let mut e = event_of_kind(kind);
        e.pubkey = pubkey.to_owned();
        e
    }

    #[test]
    fn locked_kinds_closed_by_default() {
        // No authors configured: kinds 1 and 30023 are rejected for everyone.
        let admission = Admission::from_settings(&floonet_settings());
        for kind in LOCKED_KINDS {
            match admission.check(&event_from(kind, AUTH_HEX), None) {
                Decision::Deny { auth_required, .. } => assert!(!auth_required),
                Decision::Allow => panic!("kind {kind} must be closed by default"),
            }
        }
    }

    #[test]
    fn locked_kind_from_unauthorized_key_denied() {
        let mut settings = floonet_settings();
        settings.authorization.public_note_authors = Some(vec![AUTH_HEX.to_owned()]);
        let admission = Admission::from_settings(&settings);
        let stranger = "bb".repeat(32);
        for kind in LOCKED_KINDS {
            assert_ne!(
                admission.check(&event_from(kind, &stranger), None),
                Decision::Allow,
                "kind {kind} from an unauthorized key must be denied"
            );
        }
    }

    #[test]
    fn locked_kind_from_authorized_hex_accepted() {
        let mut settings = floonet_settings();
        settings.authorization.public_note_authors = Some(vec![AUTH_HEX.to_owned()]);
        let admission = Admission::from_settings(&settings);
        for kind in LOCKED_KINDS {
            assert_eq!(
                admission.check(&event_from(kind, AUTH_HEX), None),
                Decision::Allow,
                "kind {kind} from the authorized hex key must be accepted"
            );
        }
    }

    #[test]
    fn locked_kind_from_authorized_npub_accepted() {
        // Same key, configured as an npub instead of hex.
        let mut settings = floonet_settings();
        settings.authorization.public_note_authors = Some(vec![AUTH_NPUB.to_owned()]);
        let admission = Admission::from_settings(&settings);
        for kind in LOCKED_KINDS {
            assert_eq!(
                admission.check(&event_from(kind, AUTH_HEX), None),
                Decision::Allow,
                "kind {kind} from the authorized npub must be accepted"
            );
        }
    }

    #[test]
    fn non_locked_kinds_unaffected_by_random_keys() {
        // No authors configured; profiles, gift wraps, and marketplace
        // listings from arbitrary keys are still accepted (kind 0 stays open).
        let admission = Admission::from_settings(&floonet_settings());
        let stranger = "cc".repeat(32);
        for kind in [0u64, 1059, 30402] {
            assert_eq!(
                admission.check(&event_from(kind, &stranger), None),
                Decision::Allow,
                "kind {kind} must be unaffected by the public-note lockdown"
            );
        }
    }

    #[test]
    fn malformed_authors_skipped_valid_survives() {
        let mut settings = floonet_settings();
        settings.authorization.public_note_authors = Some(vec![
            "npub1notvalid".to_owned(),
            "dead".to_owned(),
            AUTH_HEX.to_owned(),
        ]);
        let admission = Admission::from_settings(&settings);
        assert_eq!(
            admission.check(&event_from(1, AUTH_HEX), None),
            Decision::Allow
        );
        assert_ne!(
            admission.check(&event_from(1, &"bb".repeat(32)), None),
            Decision::Allow
        );
    }

    #[test]
    fn lockdown_denies_before_auth_check() {
        // With auth required, a locked kind from an unauthorized key is denied
        // by the lockdown (not an auth issue) before the auth gate runs.
        let mut settings = floonet_settings();
        settings.authorization.nip42_auth = true;
        settings.authorization.require_auth_to_write = true;
        settings.authorization.public_note_authors = Some(vec![AUTH_HEX.to_owned()]);
        let admission = Admission::from_settings(&settings);
        match admission.check(&event_from(1, &"bb".repeat(32)), Some(AUTH_HEX)) {
            Decision::Deny { auth_required, .. } => assert!(!auth_required),
            Decision::Allow => panic!("must deny unauthorized author"),
        }
    }

    // --- Gift-wrap retention/shape guard (kind 1059) ---

    fn giftwrap_with_tags(tags: Vec<Vec<String>>) -> Event {
        let mut e = event_of_kind(GIFT_WRAP_KIND);
        e.tags = tags;
        e
    }

    #[test]
    fn giftwrap_expiration_tag_rejected() {
        let admission = Admission::from_settings(&floonet_settings());
        let recipient = "aa".repeat(32);
        let event = giftwrap_with_tags(vec![
            tag(&["p", &recipient]),
            tag(&["expiration", "1700000100"]),
        ]);
        match admission.check(&event, None) {
            Decision::Deny {
                reason,
                auth_required,
            } => {
                assert!(!auth_required);
                assert!(reason.contains("expiration not allowed"), "{reason}");
            }
            Decision::Allow => panic!("gift wrap with expiration must be rejected"),
        }
    }

    #[test]
    fn giftwrap_no_p_tag_rejected() {
        let admission = Admission::from_settings(&floonet_settings());
        let event = giftwrap_with_tags(vec![]);
        match admission.check(&event, None) {
            Decision::Deny { reason, .. } => {
                assert!(reason.contains("missing recipient"), "{reason}");
            }
            Decision::Allow => panic!("gift wrap with no p tag must be rejected"),
        }
    }

    #[test]
    fn giftwrap_multiple_p_tags_rejected() {
        let admission = Admission::from_settings(&floonet_settings());
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let event = giftwrap_with_tags(vec![tag(&["p", &a]), tag(&["p", &b])]);
        match admission.check(&event, None) {
            Decision::Deny { reason, .. } => {
                assert!(reason.contains("missing recipient"), "{reason}");
            }
            Decision::Allow => panic!("gift wrap with multiple p tags must be rejected"),
        }
    }

    #[test]
    fn giftwrap_malformed_p_tag_rejected() {
        let admission = Admission::from_settings(&floonet_settings());
        for bad in ["short", &"z".repeat(64), ""] {
            let event = giftwrap_with_tags(vec![tag(&["p", bad])]);
            match admission.check(&event, None) {
                Decision::Deny { reason, .. } => {
                    assert!(reason.contains("missing recipient"), "{bad:?}: {reason}");
                }
                Decision::Allow => panic!("malformed p tag {bad:?} must be rejected"),
            }
        }
        // A `p` tag present but with no value at all (single-element tag).
        let event = giftwrap_with_tags(vec![tag(&["p"])]);
        match admission.check(&event, None) {
            Decision::Deny { reason, .. } => assert!(reason.contains("missing recipient")),
            Decision::Allow => panic!("p tag with no value must be rejected"),
        }
    }

    #[test]
    fn giftwrap_valid_single_p_no_expiration_accepted() {
        let admission = Admission::from_settings(&floonet_settings());
        let recipient = "aa".repeat(32);
        let event = giftwrap_with_tags(vec![tag(&["p", &recipient])]);
        assert_eq!(admission.check(&event, None), Decision::Allow);
    }

    #[test]
    fn non_giftwrap_with_expiration_unaffected() {
        // Expiration tags are fine on every other kind; only 1059 is guarded.
        // Kind 1 is a locked public-note kind, so authorize the author to
        // isolate this test to the gift-wrap guard.
        let mut settings = floonet_settings();
        settings.authorization.public_note_authors = Some(vec![AUTH_HEX.to_owned()]);
        let admission = Admission::from_settings(&settings);
        let mut event = event_from(1, AUTH_HEX);
        event.tags = vec![tag(&["expiration", "1700000100"])];
        assert_eq!(admission.check(&event, None), Decision::Allow);
    }

    #[test]
    fn giftwrap_guard_runs_before_auth_check() {
        // Malformed gift-wrap shape is caught even when auth would otherwise
        // gate the write; the shape check must run first.
        let mut settings = floonet_settings();
        settings.authorization.nip42_auth = true;
        settings.authorization.require_auth_to_write = true;
        let admission = Admission::from_settings(&settings);
        let recipient = "aa".repeat(32);
        let event = giftwrap_with_tags(vec![
            tag(&["expiration", "1700000100"]),
            tag(&["p", &recipient]),
        ]);
        match admission.check(&event, None) {
            Decision::Deny {
                reason,
                auth_required,
            } => {
                assert!(!auth_required, "must be the shape guard, not the auth gate");
                assert!(reason.contains("expiration not allowed"), "{reason}");
            }
            Decision::Allow => panic!("must deny"),
        }
    }
}
