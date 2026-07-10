//! End-to-end tests for the Floonet default-deny kind whitelist: a real
//! relay, a real websocket, real signed events. An allowed kind gets
//! OK=true; a disallowed kind gets OK=false with a `blocked:` reason.

use anyhow::Result;
use bitcoin_hashes::{sha256, Hash};
use floonet_rs::event::Event;
use floonet_rs::utils::unix_time;
use futures::SinkExt;
use futures::StreamExt;
use secp256k1::{rand, KeyPair, Secp256k1, XOnlyPublicKey};
use serde_json::Value;

mod common;

/// Build a signed event of `kind` and return (event_json, event_id).
fn signed_event(kind: u64, content: &str) -> (String, String) {
    signed_event_with_tags(kind, content, vec![])
}

/// Build a signed event of `kind` with the given tags and return
/// (event_json, event_id).
fn signed_event_with_tags(kind: u64, content: &str, tags: Vec<Vec<String>>) -> (String, String) {
    let secp = Secp256k1::new();
    let key_pair = KeyPair::new(&secp, &mut rand::thread_rng());
    let public_key = XOnlyPublicKey::from_keypair(&key_pair);

    let mut event = Event {
        id: "0".to_owned(),
        pubkey: public_key.to_string(),
        delegated_by: None,
        created_at: unix_time(),
        kind,
        tags,
        content: content.to_owned(),
        sig: "0".to_owned(),
        tagidx: None,
    };
    let canonical = event.to_canonical().unwrap();
    let digest: sha256::Hash = sha256::Hash::hash(canonical.as_bytes());
    let msg = secp256k1::Message::from_slice(digest.as_ref()).unwrap();
    let sig = secp.sign_schnorr(&msg, &key_pair);
    event.id = format!("{digest:x}");
    event.sig = sig.to_string();
    let json = serde_json::to_string(&event).unwrap();
    (format!(r#"["EVENT",{json}]"#), event.id)
}

/// Publish a message and return the relay's OK frame for that event id.
async fn publish_and_get_ok(port: u16, msg: &str, event_id: &str) -> Result<Value> {
    let (mut ws, _res) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}")).await?;
    ws.send(msg.into()).await?;
    // Read frames until the OK for our event id shows up.
    while let Some(frame) = ws.next().await {
        let frame = frame?;
        if let Ok(text) = frame.into_text() {
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                if value.get(0).and_then(Value::as_str) == Some("OK")
                    && value.get(1).and_then(Value::as_str) == Some(event_id)
                {
                    ws.close(None).await.ok();
                    return Ok(value);
                }
            }
        }
    }
    anyhow::bail!("no OK frame received for event {event_id}");
}

#[tokio::test]
async fn whitelist_accepts_allowed_kind_and_rejects_disallowed() -> Result<()> {
    let relay = common::start_relay()?;
    common::wait_for_healthy_relay(&relay).await?;

    // Kind 30023 (long-form article) is NOT in the Floonet whitelist: rejected.
    let (msg, id) = signed_event(30023, "hello world");
    let ok = publish_and_get_ok(relay.port, &msg, &id).await?;
    assert_eq!(
        ok.get(2).and_then(Value::as_bool),
        Some(false),
        "kind 30023 must be rejected: {ok}"
    );
    let reason = ok.get(3).and_then(Value::as_str).unwrap_or_default();
    assert!(
        reason.starts_with("blocked:"),
        "rejection must be a blocked: OK message, got {reason}"
    );

    // Kind 0 (profile metadata) IS in the whitelist: accepted.
    let (msg, id) = signed_event(0, r#"{"name":"floonet-test"}"#);
    let ok = publish_and_get_ok(relay.port, &msg, &id).await?;
    assert_eq!(
        ok.get(2).and_then(Value::as_bool),
        Some(true),
        "kind 0 must be accepted: {ok}"
    );

    // Kind 1059 (gift wrap) IS in the whitelist: accepted, provided it is a
    // well-formed NIP-59 wrap with exactly one lowercase-hex `p` recipient
    // tag (the GiftWrapRetention admission guard rejects a tagless wrap).
    let recipient = "aa".repeat(32);
    let (msg, id) = signed_event_with_tags(
        1059,
        "opaque ciphertext",
        vec![vec!["p".to_owned(), recipient]],
    );
    let ok = publish_and_get_ok(relay.port, &msg, &id).await?;
    assert_eq!(
        ok.get(2).and_then(Value::as_bool),
        Some(true),
        "kind 1059 must be accepted: {ok}"
    );

    let _res = relay.shutdown_tx.send(());
    Ok(())
}
