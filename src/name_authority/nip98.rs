//! NIP-98 HTTP authorization: verify an `Authorization: Nostr <base64>`
//! header carrying a signed kind-27235 event, including signature,
//! freshness, and the `u`/`method`/`payload` tags. The `u` tag is checked
//! against the configured public base URL, so a wrong base_url silently
//! fails every authenticated call (fail closed).
//!
//! Ported from goblin-nip05d, reusing this relay's own event validation
//! (id digest + schnorr signature) instead of an external nostr crate.

use crate::event::Event;
use crate::utils::unix_time;
use base64::Engine;
use bitcoin_hashes::{sha256, Hash};

/// NIP-98 HTTP auth event kind.
pub const HTTP_AUTH_KIND: u64 = 27235;

/// Verify a NIP-98 auth header for `method`+`url_path` over `body`.
/// On success returns (authenticated pubkey hex, auth event id hex).
pub fn verify_nip98(
    auth_header: Option<&str>,
    method: &str,
    url_path: &str,
    body: &[u8],
    base_url: &str,
    auth_max_age_secs: i64,
) -> Result<(String, String), String> {
    let auth = auth_header.ok_or("missing Authorization header")?;
    let b64 = auth
        .strip_prefix("Nostr ")
        .ok_or("Authorization scheme must be Nostr")?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| "invalid base64 auth event")?;
    let event: Event =
        serde_json::from_slice(&raw).map_err(|_| "invalid auth event json")?;
    event.validate().map_err(|_| "bad event signature")?;

    if event.kind != HTTP_AUTH_KIND {
        return Err("auth event kind must be 27235".to_string());
    }
    let age = (unix_time() as i64) - (event.created_at as i64);
    // Allow modest backward skew but only a few seconds forward, to bound
    // the replay window (paired with one-time event-id enforcement at the
    // caller).
    if age > auth_max_age_secs || age < -5 {
        return Err("auth event expired or post-dated".to_string());
    }

    let mut u_ok = false;
    let mut method_ok = false;
    let mut payload_hash: Option<String> = None;
    for tag in &event.tags {
        match tag.first().map(String::as_str) {
            Some("u") => {
                if let Some(u) = tag.get(1) {
                    let expected = format!("{base_url}{url_path}");
                    let normalized = u.trim_end_matches('/');
                    u_ok = normalized == expected.trim_end_matches('/');
                }
            }
            Some("method") => {
                if let Some(m) = tag.get(1) {
                    method_ok = m.eq_ignore_ascii_case(method);
                }
            }
            Some("payload") => {
                payload_hash = tag.get(1).cloned();
            }
            _ => {}
        }
    }
    if !u_ok {
        return Err("auth event url mismatch".to_string());
    }
    if !method_ok {
        return Err("auth event method mismatch".to_string());
    }
    if let Some(expect) = payload_hash {
        let digest: sha256::Hash = sha256::Hash::hash(body);
        let got = format!("{digest:x}");
        if !expect.eq_ignore_ascii_case(&got) {
            return Err("auth event payload hash mismatch".to_string());
        }
    } else if !body.is_empty() {
        return Err("auth event missing payload hash".to_string());
    }

    Ok((event.pubkey.clone(), event.id.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use bitcoin_hashes::{sha256, Hash};
    use secp256k1::{KeyPair, Secp256k1, XOnlyPublicKey};

    /// Build and sign a real NIP-98 event for tests.
    fn signed_auth_event(
        url: &str,
        method: &str,
        body: Option<&[u8]>,
        kind: u64,
        created_at: u64,
    ) -> String {
        let secp = Secp256k1::new();
        let keypair = KeyPair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair);
        let pubkey_hex = pubkey.to_string();

        let mut tags: Vec<Vec<String>> = vec![
            vec!["u".to_string(), url.to_string()],
            vec!["method".to_string(), method.to_string()],
        ];
        if let Some(body) = body {
            let digest: sha256::Hash = sha256::Hash::hash(body);
            tags.push(vec!["payload".to_string(), format!("{digest:x}")]);
        }
        let mut event = Event {
            id: String::new(),
            pubkey: pubkey_hex,
            delegated_by: None,
            created_at,
            kind,
            tags,
            content: String::new(),
            sig: String::new(),
            tagidx: None,
        };
        let canonical = event.to_canonical().unwrap();
        let digest: sha256::Hash = sha256::Hash::hash(canonical.as_bytes());
        event.id = format!("{digest:x}");
        let msg = secp256k1::Message::from_slice(digest.as_ref()).unwrap();
        event.sig = secp.sign_schnorr(&msg, &keypair).to_string();

        let json = serde_json::to_string(&event).unwrap();
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(json)
        )
    }

    #[test]
    fn accepts_valid_auth() {
        let base = "https://names.example";
        let body = br#"{"name":"ada","pubkey":"aa"}"#;
        let header = signed_auth_event(
            &format!("{base}/api/v1/register"),
            "POST",
            Some(body),
            HTTP_AUTH_KIND,
            unix_time(),
        );
        let res = verify_nip98(
            Some(&header),
            "POST",
            "/api/v1/register",
            body,
            base,
            60,
        );
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn rejects_wrong_kind() {
        let base = "https://names.example";
        let header = signed_auth_event(
            &format!("{base}/api/v1/register"),
            "POST",
            None,
            1,
            unix_time(),
        );
        assert!(
            verify_nip98(Some(&header), "POST", "/api/v1/register", &[], base, 60).is_err()
        );
    }

    #[test]
    fn rejects_stale_event() {
        let base = "https://names.example";
        let header = signed_auth_event(
            &format!("{base}/api/v1/register"),
            "POST",
            None,
            HTTP_AUTH_KIND,
            unix_time() - 3600,
        );
        assert!(
            verify_nip98(Some(&header), "POST", "/api/v1/register", &[], base, 60).is_err()
        );
    }

    #[test]
    fn rejects_url_mismatch() {
        let base = "https://names.example";
        let header = signed_auth_event(
            "https://evil.example/api/v1/register",
            "POST",
            None,
            HTTP_AUTH_KIND,
            unix_time(),
        );
        assert!(
            verify_nip98(Some(&header), "POST", "/api/v1/register", &[], base, 60).is_err()
        );
    }

    #[test]
    fn rejects_method_mismatch() {
        let base = "https://names.example";
        let header = signed_auth_event(
            &format!("{base}/api/v1/register"),
            "DELETE",
            None,
            HTTP_AUTH_KIND,
            unix_time(),
        );
        assert!(
            verify_nip98(Some(&header), "POST", "/api/v1/register", &[], base, 60).is_err()
        );
    }

    #[test]
    fn rejects_payload_tampering() {
        let base = "https://names.example";
        let body = br#"{"name":"ada"}"#;
        let header = signed_auth_event(
            &format!("{base}/api/v1/register"),
            "POST",
            Some(body),
            HTTP_AUTH_KIND,
            unix_time(),
        );
        let tampered = br#"{"name":"eve"}"#;
        assert!(verify_nip98(
            Some(&header),
            "POST",
            "/api/v1/register",
            tampered,
            base,
            60
        )
        .is_err());
    }

    #[test]
    fn rejects_missing_header_and_bad_scheme() {
        assert!(verify_nip98(None, "POST", "/x", &[], "https://a", 60).is_err());
        assert!(verify_nip98(Some("Bearer zzz"), "POST", "/x", &[], "https://a", 60).is_err());
    }
}
