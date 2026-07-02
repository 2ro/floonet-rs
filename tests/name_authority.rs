//! End-to-end tests for the built-in name authority: NIP-98 registration
//! round trip, NIP-05 resolution, reverse lookup, one-name-per-key,
//! reserved names, release + cooldown, plus the paid-name flow against a
//! fake GoblinPay server (402 until the invoice reports paid). Also
//! verifies the NIP-11 document stays payment-free.

use anyhow::Result;
use base64::Engine;
use bitcoin_hashes::{sha256, Hash};
use floonet_rs::event::Event;
use floonet_rs::utils::unix_time;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Server, StatusCode};
use secp256k1::{KeyPair, Secp256k1, XOnlyPublicKey};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod common;

/// A test identity that can sign NIP-98 auth events.
struct Signer {
    secp: Secp256k1<secp256k1::All>,
    keypair: KeyPair,
    pub pubkey_hex: String,
}

impl Signer {
    fn new(seed: u8) -> Signer {
        let secp = Secp256k1::new();
        let keypair = KeyPair::from_seckey_slice(&secp, &[seed; 32]).unwrap();
        let pubkey_hex = XOnlyPublicKey::from_keypair(&keypair).to_string();
        Signer {
            secp,
            keypair,
            pubkey_hex,
        }
    }

    /// `Authorization: Nostr <b64>` header for method+url over body.
    fn nip98(&self, url: &str, method: &str, body: &[u8]) -> String {
        let mut tags: Vec<Vec<String>> = vec![
            vec!["u".to_string(), url.to_string()],
            vec!["method".to_string(), method.to_string()],
            // A nonce keeps every auth event id unique, so back-to-back
            // requests in the same second are not misread as replays.
            vec!["nonce".to_string(), format!("{:x}", rand_u64())],
        ];
        if !body.is_empty() {
            let digest: sha256::Hash = sha256::Hash::hash(body);
            tags.push(vec!["payload".to_string(), format!("{digest:x}")]);
        }
        let mut event = Event {
            id: "0".to_owned(),
            pubkey: self.pubkey_hex.clone(),
            delegated_by: None,
            created_at: unix_time(),
            kind: 27235,
            tags,
            content: String::new(),
            sig: "0".to_owned(),
            tagidx: None,
        };
        let canonical = event.to_canonical().unwrap();
        let digest: sha256::Hash = sha256::Hash::hash(canonical.as_bytes());
        let msg = secp256k1::Message::from_slice(digest.as_ref()).unwrap();
        event.id = format!("{digest:x}");
        event.sig = self.secp.sign_schnorr(&msg, &self.keypair).to_string();
        let json = serde_json::to_string(&event).unwrap();
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(json)
        )
    }
}

fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Cheap uniqueness for test nonces.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

async fn get_json(url: &str) -> Result<(StatusCode, Value)> {
    let client = Client::new();
    let res = client.get(url.parse()?).await?;
    let status = res.status();
    let bytes = hyper::body::to_bytes(res.into_body()).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn register(
    base: &str,
    signer: Option<&Signer>,
    name: &str,
    pubkey: &str,
) -> Result<(StatusCode, Value)> {
    let body = json!({"name": name, "pubkey": pubkey}).to_string();
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("{base}/api/v1/register"))
        .header("Content-Type", "application/json");
    if let Some(signer) = signer {
        builder = builder.header(
            "Authorization",
            signer.nip98(&format!("{base}/api/v1/register"), "POST", body.as_bytes()),
        );
    }
    let res = Client::new()
        .request(builder.body(Body::from(body))?)
        .await?;
    let status = res.status();
    let bytes = hyper::body::to_bytes(res.into_body()).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn unregister(base: &str, signer: &Signer, name: &str) -> Result<(StatusCode, Value)> {
    let url = format!("{base}/api/v1/register/{name}");
    let req = Request::builder()
        .method("DELETE")
        .uri(&url)
        .header("Authorization", signer.nip98(&url, "DELETE", &[]))
        .body(Body::empty())?;
    let res = Client::new().request(req).await?;
    let status = res.status();
    let bytes = hyper::body::to_bytes(res.into_body()).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

/// Fresh file-backed data directory (exercises the v19 migration).
fn temp_data_dir(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("floonet-rs-test-{tag}-{}", rand_u64()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().into_owned()
}

fn authority_relay(data_dir: &str) -> Result<common::Relay> {
    let data_dir = data_dir.to_owned();
    common::start_relay_with(move |settings| {
        settings.database.in_memory = false;
        settings.database.data_directory = data_dir;
        settings.name_authority.enabled = true;
        settings.name_authority.domain = "names.example".to_owned();
        settings.name_authority.base_url = format!("http://127.0.0.1:{}", settings.network.port);
        settings.name_authority.name_change_cooldown_secs = 600;
    })
}

#[tokio::test]
async fn name_authority_round_trip() -> Result<()> {
    let data_dir = temp_data_dir("authority");
    let relay = authority_relay(&data_dir)?;
    common::wait_for_healthy_relay(&relay).await?;
    let base = format!("http://127.0.0.1:{}", relay.port);
    let alice = Signer::new(11);
    let bob = Signer::new(22);

    // Health.
    let res = Client::new()
        .get(format!("{base}/api/v1/health").parse()?)
        .await?;
    assert_eq!(res.status(), StatusCode::OK);

    // Availability before any claim.
    let (status, body) = get_json(&format!("{base}/api/v1/name/ada")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["available"], json!(true));

    // Unauthenticated register is refused.
    let (status, _) = register(&base, None, "ada", &alice.pubkey_hex).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // NIP-98 authenticated register succeeds.
    let (status, body) = register(&base, Some(&alice), "ada", &alice.pubkey_hex).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["nip05"], json!("ada@names.example"));

    // NIP-05 resolution.
    let (status, body) =
        get_json(&format!("{base}/.well-known/nostr.json?name=ada")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["names"]["ada"], json!(alice.pubkey_hex));

    // Reverse lookup.
    let (status, body) =
        get_json(&format!("{base}/api/v1/by-pubkey/{}", alice.pubkey_hex)).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], json!("ada"));

    // Same name, different key: conflict.
    let (status, _) = register(&base, Some(&bob), "ada", &bob.pubkey_hex).await?;
    assert_eq!(status, StatusCode::CONFLICT);

    // One active name per key.
    let (status, body) = register(&base, Some(&alice), "ada2", &alice.pubkey_hex).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Reserved and look-alike names are refused.
    let (status, _) = register(&base, Some(&bob), "admin", &bob.pubkey_hex).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = register(&base, Some(&bob), "supp0rt", &bob.pubkey_hex).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The operator's own domain label is reserved too.
    let (status, _) = register(&base, Some(&bob), "names", &bob.pubkey_hex).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Release, then the release-armed cooldown blocks a fresh claim.
    let (status, body) = unregister(&base, &alice, "ada").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = register(&base, Some(&alice), "lovelace", &alice.pubkey_hex).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], json!("name_change_cooldown"));

    // The released name resolves to nobody.
    let (_, body) = get_json(&format!("{base}/.well-known/nostr.json?name=ada")).await?;
    assert_eq!(body["names"], json!({}));

    let _res = relay.shutdown_tx.send(());
    std::fs::remove_dir_all(&data_dir).ok();
    Ok(())
}

#[tokio::test]
async fn nip11_and_landing_are_payment_free() -> Result<()> {
    let relay = common::start_relay()?;
    common::wait_for_healthy_relay(&relay).await?;
    let base = format!("http://127.0.0.1:{}", relay.port);

    // NIP-11 document: neutral Floonet identity, zero payment wording.
    let req = Request::builder()
        .method("GET")
        .uri(&base)
        .header("Accept", "application/nostr+json")
        .body(Body::empty())?;
    let res = Client::new().request(req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = hyper::body::to_bytes(res.into_body()).await?;
    let text = String::from_utf8(bytes.to_vec())?;
    let info: Value = serde_json::from_str(&text)?;
    assert_eq!(info["name"], json!("floonet-rs-relay"));
    for banned in ["payment", "fees", "sats", "msats", "invoice", "slatepack"] {
        assert!(
            !text.to_lowercase().contains(banned),
            "NIP-11 must not mention `{banned}`: {text}"
        );
    }

    // Landing page shows the Floonet branding and references the logo.
    let res = Client::new().get(base.parse()?).await?;
    let bytes = hyper::body::to_bytes(res.into_body()).await?;
    let html = String::from_utf8(bytes.to_vec())?;
    assert!(html.contains("/logo.svg"), "landing must show the logo");
    assert!(
        !html.to_lowercase().contains("payment"),
        "landing must not mention payments"
    );

    // The logo itself is served.
    let res = Client::new().get(format!("{base}/logo.svg").parse()?).await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "image/svg+xml"
    );

    let _res = relay.shutdown_tx.send(());
    Ok(())
}

/// Minimal fake GoblinPay: POST /invoice and GET /invoice/{id}, with a
/// shared "paid" flag the test flips.
async fn fake_goblinpay(paid: Arc<AtomicBool>) -> Result<String> {
    let make_svc = make_service_fn(move |_conn| {
        let paid = paid.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let paid = paid.clone();
                async move {
                    let authed = req
                        .headers()
                        .get("Authorization")
                        .and_then(|v| v.to_str().ok())
                        == Some("Bearer test-gp-token");
                    let status = if paid.load(Ordering::SeqCst) {
                        "paid"
                    } else {
                        "open"
                    };
                    let response = if !authed {
                        hyper::Response::builder()
                            .status(401)
                            .body(Body::from(r#"{"error":"unauthorized"}"#))
                            .unwrap()
                    } else {
                        hyper::Response::builder()
                            .status(200)
                            .header("Content-Type", "application/json")
                            .body(Body::from(
                                json!({
                                    "invoice_id": "inv-test-1",
                                    "token": "tok1",
                                    "pay_url": "http://pay.invalid/pay/tok1",
                                    "status": status,
                                })
                                .to_string(),
                            ))
                            .unwrap()
                    };
                    Ok::<_, Infallible>(response)
                }
            }))
        }
    });
    let server = Server::bind(&"127.0.0.1:0".parse()?).serve(make_svc);
    let addr = server.local_addr();
    tokio::spawn(async move {
        let _ = server.await;
    });
    Ok(format!("http://{addr}"))
}

#[tokio::test]
async fn paid_names_require_confirmed_goblinpay_payment() -> Result<()> {
    let paid = Arc::new(AtomicBool::new(false));
    let gp_url = fake_goblinpay(paid.clone()).await?;

    let data_dir = temp_data_dir("paid");
    let relay = {
        let data_dir = data_dir.clone();
        common::start_relay_with(move |settings| {
            settings.database.in_memory = false;
            settings.database.data_directory = data_dir;
            settings.name_authority.enabled = true;
            settings.name_authority.domain = "names.example".to_owned();
            settings.name_authority.base_url =
                format!("http://127.0.0.1:{}", settings.network.port);
            settings.goblinpay.pay_mode = "name".to_owned();
            settings.goblinpay.url = gp_url;
            settings.goblinpay.api_token = "test-gp-token".to_owned();
            settings.goblinpay.name_price_grin = 2.5;
        })?
    };
    common::wait_for_healthy_relay(&relay).await?;
    let base = format!("http://127.0.0.1:{}", relay.port);
    let alice = Signer::new(33);

    // Unpaid: register answers 402 with the GoblinPay pay page.
    let (status, body) = register(&base, Some(&alice), "ada", &alice.pubkey_hex).await?;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{body}");
    assert_eq!(body["error"], json!("payment_required"));
    assert_eq!(body["pay_url"], json!("http://pay.invalid/pay/tok1"));
    assert_eq!(body["invoice_id"], json!("inv-test-1"));
    assert_eq!(body["price_grin"], json!(2.5));
    assert_eq!(body["price_nanogrin"], json!(2_500_000_000u64));

    // Still unpaid on retry: the same outstanding invoice comes back.
    let (status, body) = register(&base, Some(&alice), "ada", &alice.pubkey_hex).await?;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{body}");
    assert_eq!(body["invoice_id"], json!("inv-test-1"));

    // Payment confirms on chain (GoblinPay now reports paid): claim works.
    paid.store(true, Ordering::SeqCst);
    let (status, body) = register(&base, Some(&alice), "ada", &alice.pubkey_hex).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["nip05"], json!("ada@names.example"));

    // And the name resolves.
    let (_, body) = get_json(&format!("{base}/.well-known/nostr.json?name=ada")).await?;
    assert_eq!(body["names"]["ada"], json!(alice.pubkey_hex));

    let _res = relay.shutdown_tx.send(());
    std::fs::remove_dir_all(&data_dir).ok();
    Ok(())
}
