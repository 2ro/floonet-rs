//! Built-in name authority (Floonet addition).
//!
//! `name@domain` NIP-05 resolution with NIP-98 authenticated self-service
//! registration, ported from goblin-nip05d and served in-process on the
//! relay's own HTTP listener. Claims live in the relay database
//! (`name_claims` table, sqlite engine); everything else (rate limits,
//! replay window, cooldowns) is in-memory and resets on restart.
//!
//! Endpoints:
//! * `GET  /.well-known/nostr.json?name=<name>` NIP-05 resolution
//! * `POST /api/v1/register`                    claim a name (NIP-98)
//! * `DELETE /api/v1/register/{name}`           release a name (NIP-98)
//! * `GET  /api/v1/name/{name}`                 availability
//! * `GET  /api/v1/profile/{name}`              name -> pubkey
//! * `GET  /api/v1/by-pubkey/{pubkey}`          pubkey -> name (reverse)
//! * `GET  /api/v1/health`                      liveness
//!
//! Paid names: when `goblinpay.pay_mode = "name"`, a first-time claim
//! returns `402 {"error":"payment_required", "pay_url": ...}` carrying a
//! GoblinPay invoice. Once the payment confirms on chain the same
//! register call succeeds. Payment state reuses the relay's existing
//! `account`/`invoice` tables and the `PaymentProcessor` trait.

pub mod names;
pub mod nip98;

use crate::config::Settings;
use crate::error::{Error, Result};
use crate::payment::goblinpay::GoblinPayPaymentProcessor;
use crate::payment::{InvoiceStatus, PaymentProcessor};
use crate::repo::NostrRepo;
use crate::utils::unix_time;
use hyper::body::HttpBody;
use hyper::{Body, Method, Request, Response, StatusCode};
use nostr::key::FromPkStr;
use nostr::Keys;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Largest register body we accept (fail closed on anything bigger).
const MAX_BODY_BYTES: u64 = 8192;

/// True when this path belongs to the name authority.
#[must_use]
pub fn is_authority_path(path: &str) -> bool {
    path == "/.well-known/nostr.json" || path.starts_with("/api/v1/")
}

/// Resolved paid-names state.
enum PaidNames {
    Free,
    Paid {
        processor: Arc<dyn PaymentProcessor>,
        price_nanogrin: u64,
        price_grin: f64,
    },
}

pub struct Authority {
    cfg: crate::config::NameAuthority,
    /// Relays advertised in `/.well-known/nostr.json`.
    relays: Vec<String>,
    /// Operator domain labels + reserved-file names.
    extra_reserved: Vec<String>,
    /// Header carrying the real client IP (set by the reverse proxy).
    remote_ip_header: Option<String>,
    /// Claims store: an extra connection to the relay's own sqlite DB
    /// (the `name_claims` table is created by the relay migration).
    db: Mutex<rusqlite::Connection>,
    /// Per-IP sliding windows and per-pubkey cooldowns.
    rate: Mutex<HashMap<String, Vec<Instant>>>,
    /// Seen NIP-98 auth event ids (one-time use in the freshness window).
    seen_auth: Mutex<HashMap<String, Instant>>,
    /// Relay repository, reused for paid-name account/invoice state.
    repo: Arc<dyn NostrRepo>,
    paid: PaidNames,
}

impl Authority {
    /// Build the authority from settings. The relay migration has already
    /// created the `name_claims` table by the time this runs.
    pub fn new(settings: &Settings, repo: Arc<dyn NostrRepo>) -> Result<Authority> {
        let cfg = settings.name_authority.clone();
        let db_path = Path::new(&settings.database.data_directory).join(crate::db::DB_FILE);
        let conn = rusqlite::Connection::open(db_path).map_err(Error::SqlError)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(Error::SqlError)?;
        // The relay migration (v19) creates this table for file-backed
        // databases; applying the same idempotent DDL here keeps the
        // authority working when the relay runs an in-memory event store.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS name_claims (
                name TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                released_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS name_claims_pubkey_index ON name_claims(pubkey);
            CREATE UNIQUE INDEX IF NOT EXISTS name_claims_active_pubkey
                ON name_claims(pubkey) WHERE released_at IS NULL;",
        )
        .map_err(Error::SqlError)?;

        let relays = match &cfg.relays {
            Some(relays) if !relays.is_empty() => relays.clone(),
            _ => settings.info.relay_url.iter().cloned().collect(),
        };

        // Reserve the operator's own domain labels, then any names from
        // the optional reserved file.
        let mut extra_reserved = names::domain_reserved(&cfg.domain);
        if let Some(path) = cfg.reserved_file.as_ref().filter(|p| !p.is_empty()) {
            let text = std::fs::read_to_string(path).map_err(|e| {
                Error::CustomError(format!("name_authority.reserved_file `{path}` unreadable: {e}"))
            })?;
            extra_reserved.extend(
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_lowercase),
            );
        }

        let paid = if settings.goblinpay.pay_mode == "name" {
            info!(
                "name authority: paid names enabled ({} GRIN per name)",
                settings.goblinpay.name_price_grin
            );
            PaidNames::Paid {
                processor: Arc::new(GoblinPayPaymentProcessor::new(
                    &settings.goblinpay.url,
                    &settings.goblinpay.api_token,
                )),
                price_nanogrin: settings.goblinpay.name_price_nanogrin(),
                price_grin: settings.goblinpay.name_price_grin,
            }
        } else {
            PaidNames::Free
        };

        info!(
            "name authority enabled: domain={} base_url={} relays={:?} names {}..={} chars",
            cfg.domain, cfg.base_url, relays, cfg.name_min, cfg.name_max
        );

        Ok(Authority {
            cfg,
            relays,
            extra_reserved,
            remote_ip_header: settings.network.remote_ip_header.clone(),
            db: Mutex::new(conn),
            rate: Mutex::new(HashMap::new()),
            seen_auth: Mutex::new(HashMap::new()),
            repo,
            paid,
        })
    }

    // ------------------------------------------------------------------
    // Claims store
    // ------------------------------------------------------------------

    /// Active (non-released) pubkey for a name.
    fn lookup(&self, name: &str) -> Option<String> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT pubkey FROM name_claims WHERE name = ?1 AND released_at IS NULL",
                [name],
                |r| r.get::<_, String>(0),
            )
            .ok()
    }

    /// Active name owned by a pubkey.
    fn name_of(&self, pubkey: &str) -> Option<String> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT name FROM name_claims WHERE pubkey = ?1 AND released_at IS NULL",
                [pubkey],
                |r| r.get::<_, String>(0),
            )
            .ok()
    }

    // ------------------------------------------------------------------
    // Rate limiting / replay / cooldowns (in-memory, reset on restart)
    // ------------------------------------------------------------------

    /// Record a NIP-98 auth event id as used; false if replayed.
    fn auth_event_fresh(&self, event_id: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.cfg.auth_max_age_secs.max(0) as u64 + 5);
        let mut seen = self.seen_auth.lock().unwrap();
        seen.retain(|_, t| now.duration_since(*t) < window);
        if seen.contains_key(event_id) {
            return false;
        }
        seen.insert(event_id.to_string(), now);
        true
    }

    /// True when an operation in this bucket happened within the window.
    fn cooldown_active(&self, bucket: &str, key: &str, window: Duration) -> bool {
        let k = format!("{bucket}:{key}");
        let now = Instant::now();
        let mut map = self.rate.lock().unwrap();
        if let Some(hits) = map.get_mut(&k) {
            hits.retain(|t| now.duration_since(*t) < window);
            return !hits.is_empty();
        }
        false
    }

    /// Record a completed operation for cooldown tracking.
    fn record_op(&self, bucket: &str, key: &str) {
        let k = format!("{bucket}:{key}");
        self.rate
            .lock()
            .unwrap()
            .entry(k)
            .or_default()
            .push(Instant::now());
    }

    /// Sliding-window per-IP limiter; true when the call is allowed.
    fn allow(&self, bucket: &str, ip: &str, max: usize, window: Duration) -> bool {
        let key = format!("{bucket}:{ip}");
        let now = Instant::now();
        let mut map = self.rate.lock().unwrap();
        let hits = map.entry(key).or_default();
        hits.retain(|t| now.duration_since(*t) < window);
        if hits.len() >= max {
            return false;
        }
        hits.push(now);
        // Opportunistic global cleanup to bound memory.
        if map.len() > 50_000 {
            map.retain(|_, v| v.iter().any(|t| now.duration_since(*t) < window));
        }
        true
    }

    fn allow_read(&self, ip: &str) -> bool {
        self.allow(
            "na-read",
            ip,
            self.cfg.read_rate_max,
            Duration::from_secs(self.cfg.read_rate_window_secs),
        )
    }

    fn allow_write(&self, bucket: &str, ip: &str) -> bool {
        self.allow(
            bucket,
            ip,
            self.cfg.write_rate_max,
            Duration::from_secs(self.cfg.write_rate_window_secs),
        )
    }

    /// Client IP for rate limiting: the configured proxy header when
    /// present (load-bearing behind a reverse proxy), else the socket.
    fn client_ip(&self, request: &Request<Body>, remote_addr: &SocketAddr) -> String {
        self.remote_ip_header
            .as_ref()
            .and_then(|h| request.headers().get(h.as_str()))
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| remote_addr.ip().to_string())
    }

    // ------------------------------------------------------------------
    // HTTP dispatch
    // ------------------------------------------------------------------

    /// Handle one authority request. Callers route here for any path
    /// where [`is_authority_path`] is true.
    pub async fn handle(
        self: &Arc<Self>,
        request: Request<Body>,
        remote_addr: SocketAddr,
    ) -> Response<Body> {
        let ip = self.client_ip(&request, &remote_addr);
        let method = request.method().clone();
        let path = request.uri().path().to_string();
        match (method, path.as_str()) {
            (Method::GET, "/.well-known/nostr.json") => self.well_known(&request, &ip),
            (Method::GET, "/api/v1/health") => text_response(StatusCode::OK, "ok"),
            (Method::GET, p) if p.starts_with("/api/v1/name/") => {
                self.availability(strip(p, "/api/v1/name/"), &ip)
            }
            (Method::GET, p) if p.starts_with("/api/v1/profile/") => {
                self.profile(strip(p, "/api/v1/profile/"), &ip)
            }
            (Method::GET, p) if p.starts_with("/api/v1/by-pubkey/") => {
                self.by_pubkey(strip(p, "/api/v1/by-pubkey/"), &ip)
            }
            (Method::POST, "/api/v1/register") => self.register(request, &ip).await,
            (Method::DELETE, p) if p.starts_with("/api/v1/register/") => {
                self.unregister(strip(p, "/api/v1/register/"), &request, &ip)
            }
            _ => json_response(StatusCode::NOT_FOUND, json!({"error": "not found"})),
        }
    }

    // ------------------------------------------------------------------
    // Read endpoints
    // ------------------------------------------------------------------

    fn well_known(&self, request: &Request<Body>, ip: &str) -> Response<Body> {
        if !self.allow_read(ip) {
            return rate_limited();
        }
        let mut result_names = serde_json::Map::new();
        let mut result_relays = serde_json::Map::new();
        if let Some(name) = query_param(request, "name").map(|n| n.to_lowercase()) {
            if names::valid_name(&name, self.cfg.name_min, self.cfg.name_max) {
                if let Some(pk) = self.lookup(&name) {
                    result_names.insert(name, json!(pk.clone()));
                    result_relays.insert(pk, json!(self.relays));
                }
            }
        }
        json_response(
            StatusCode::OK,
            json!({ "names": result_names, "relays": result_relays }),
        )
    }

    fn availability(&self, name: &str, ip: &str) -> Response<Body> {
        if !self.allow_read(ip) {
            return rate_limited();
        }
        let name = name.to_lowercase();
        if !names::valid_name(&name, self.cfg.name_min, self.cfg.name_max) {
            return json_response(
                StatusCode::OK,
                json!({"name": name, "available": false, "reason": "invalid"}),
            );
        }
        if names::is_reserved(&name, &self.extra_reserved) {
            return json_response(
                StatusCode::OK,
                json!({"name": name, "available": false, "reason": "reserved"}),
            );
        }
        if self.lookup(&name).is_some() {
            return json_response(
                StatusCode::OK,
                json!({"name": name, "available": false, "reason": "taken"}),
            );
        }
        json_response(StatusCode::OK, json!({"name": name, "available": true}))
    }

    fn profile(&self, name: &str, ip: &str) -> Response<Body> {
        if !self.allow_read(ip) {
            return rate_limited();
        }
        let name = name.to_lowercase();
        if !names::valid_name(&name, self.cfg.name_min, self.cfg.name_max) {
            return json_response(StatusCode::NOT_FOUND, json!({"error": "not found"}));
        }
        match self.lookup(&name) {
            Some(pubkey) => {
                json_response(StatusCode::OK, json!({"name": name, "pubkey": pubkey}))
            }
            None => json_response(StatusCode::NOT_FOUND, json!({"error": "not found"})),
        }
    }

    fn by_pubkey(&self, pubkey: &str, ip: &str) -> Response<Body> {
        if !self.allow_read(ip) {
            return rate_limited();
        }
        let pubkey = pubkey.to_lowercase();
        if !names::valid_pubkey_hex(&pubkey) {
            return json_response(StatusCode::NOT_FOUND, json!({"error": "not found"}));
        }
        match self.name_of(&pubkey) {
            Some(name) => {
                json_response(StatusCode::OK, json!({"name": name, "pubkey": pubkey}))
            }
            None => json_response(StatusCode::NOT_FOUND, json!({"error": "not found"})),
        }
    }

    // ------------------------------------------------------------------
    // Write endpoints (NIP-98 authenticated)
    // ------------------------------------------------------------------

    async fn register(&self, request: Request<Body>, ip: &str) -> Response<Body> {
        if !self.allow_write("na-reg", ip) {
            return rate_limited();
        }
        // Fail closed on oversized bodies before buffering anything.
        if request
            .body()
            .size_hint()
            .upper()
            .map_or(true, |n| n > MAX_BODY_BYTES)
        {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": "body too large"}),
            );
        }
        let auth_header = request
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = match hyper::body::to_bytes(request.into_body()).await {
            Ok(b) if (b.len() as u64) <= MAX_BODY_BYTES => b,
            _ => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"error": "invalid body"}),
                )
            }
        };

        let (auth_pubkey, auth_id) = match nip98::verify_nip98(
            auth_header.as_deref(),
            "POST",
            "/api/v1/register",
            &body,
            &self.cfg.base_url,
            self.cfg.auth_max_age_secs,
        ) {
            Ok(v) => v,
            Err(msg) => return json_response(StatusCode::UNAUTHORIZED, json!({"error": msg})),
        };
        if !self.auth_event_fresh(&auth_id) {
            return json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "auth event replayed"}),
            );
        }

        // The cooldown is armed by a *release*, not a claim: it blocks
        // registering a new name for the window after letting one go
        // (anti-churn). Checked after auth so strangers cannot probe it.
        if self.cooldown_active(
            "na-namechange",
            &auth_pubkey,
            Duration::from_secs(self.cfg.name_change_cooldown_secs),
        ) {
            return json_response(
                StatusCode::TOO_MANY_REQUESTS,
                json!({"error": "name_change_cooldown"}),
            );
        }

        #[derive(serde::Deserialize)]
        struct RegisterBody {
            name: String,
            pubkey: String,
        }
        let req: RegisterBody = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => {
                return json_response(StatusCode::BAD_REQUEST, json!({"error": "invalid body"}))
            }
        };
        let name = req.name.to_lowercase();
        let pubkey = req.pubkey.to_lowercase();

        if !names::valid_pubkey_hex(&pubkey) {
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "invalid pubkey"}));
        }
        if pubkey != auth_pubkey {
            return json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "auth pubkey does not match body pubkey"}),
            );
        }
        if !names::valid_name(&name, self.cfg.name_min, self.cfg.name_max) {
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "invalid name"}));
        }
        if names::is_reserved(&name, &self.extra_reserved) {
            return json_response(StatusCode::FORBIDDEN, json!({"error": "name reserved"}));
        }

        // Existing active registration of this exact name.
        if let Some(owner) = self.lookup(&name) {
            if owner == pubkey {
                return json_response(
                    StatusCode::OK,
                    json!({"name": name, "nip05": format!("{name}@{}", self.cfg.domain)}),
                );
            }
            return json_response(StatusCode::CONFLICT, json!({"error": "name taken"}));
        }
        // One active name per pubkey.
        if let Some(existing) = self.name_of(&pubkey) {
            return json_response(
                StatusCode::CONFLICT,
                json!({"error": "pubkey already has a name", "name": existing}),
            );
        }

        // Paid names: the claim only proceeds once this pubkey has a
        // confirmed payment. All validity checks ran first, so nobody is
        // asked to pay for an unclaimable name.
        if let Some(resp) = self.paid_gate(&pubkey).await {
            return resp;
        }

        // INSERT guarded by the name PRIMARY KEY and the partial-unique
        // pubkey index. The ON CONFLICT(name) only revives a released
        // name; a concurrent double-register is caught by the unique
        // index and surfaces as a constraint error -> 409.
        let res = self.db.lock().unwrap().execute(
            "INSERT INTO name_claims (name, pubkey, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET pubkey = excluded.pubkey,
                created_at = excluded.created_at, released_at = NULL
             WHERE name_claims.released_at IS NOT NULL",
            rusqlite::params![name, pubkey, unix_time()],
        );
        match res {
            // rows == 0 means the ON CONFLICT no-op fired (name already
            // active): report a conflict rather than a false success.
            Ok(0) => json_response(StatusCode::CONFLICT, json!({"error": "name taken"})),
            Ok(_) => {
                // Claiming must not arm a cooldown; only release does.
                info!("name authority: registered {name} -> {pubkey}");
                json_response(
                    StatusCode::CREATED,
                    json!({"name": name, "nip05": format!("{name}@{}", self.cfg.domain)}),
                )
            }
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                json_response(
                    StatusCode::CONFLICT,
                    json!({"error": "pubkey already has a name"}),
                )
            }
            Err(e) => {
                error!("name authority: db insert failed: {e}");
                json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "db error"}),
                )
            }
        }
    }

    /// The paid gate. Returns None when the claim may proceed (free mode,
    /// or this pubkey has a confirmed payment); otherwise the 402/5xx
    /// response to send. Payment admits the PUBKEY (relay `account` row),
    /// and each invoice is a GoblinPay invoice checked against the
    /// GoblinPay server, which only reports paid after on-chain
    /// confirmation. Fail closed: any error refuses the claim.
    async fn paid_gate(&self, pubkey: &str) -> Option<Response<Body>> {
        let PaidNames::Paid {
            processor,
            price_nanogrin,
            price_grin,
        } = &self.paid
        else {
            return None;
        };
        let keys = match Keys::from_pk_str(pubkey) {
            Ok(k) => k,
            Err(_) => {
                return Some(json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"error": "invalid pubkey"}),
                ))
            }
        };

        // Already paid?
        if let Ok((admitted, _)) = self.repo.get_account_balance(&keys).await {
            if admitted {
                return None;
            }
        }

        // Outstanding invoice? Poll GoblinPay for its status.
        if let Ok(Some(invoice)) = self.repo.get_unpaid_invoice(&keys).await {
            return match processor.check_invoice(&invoice.payment_hash).await {
                Ok(InvoiceStatus::Paid) => {
                    if self
                        .repo
                        .update_invoice(&invoice.payment_hash, InvoiceStatus::Paid)
                        .await
                        .is_err()
                        || self.repo.admit_account(&keys, *price_nanogrin).await.is_err()
                    {
                        return Some(server_error());
                    }
                    info!("name authority: payment confirmed for {pubkey}");
                    None
                }
                Ok(InvoiceStatus::Unpaid) => Some(payment_required(
                    &invoice.payment_hash,
                    &invoice.bolt11,
                    *price_grin,
                    *price_nanogrin,
                )),
                Ok(InvoiceStatus::Expired) => {
                    self.repo
                        .update_invoice(&invoice.payment_hash, InvoiceStatus::Expired)
                        .await
                        .ok();
                    Some(self.new_invoice(processor, &keys, *price_grin, *price_nanogrin).await)
                }
                Err(e) => {
                    warn!("name authority: goblinpay status check failed: {e:?}");
                    Some(server_error())
                }
            };
        }

        // First contact: create the account row and a fresh invoice.
        self.repo.create_account(&keys).await.ok();
        Some(self.new_invoice(processor, &keys, *price_grin, *price_nanogrin).await)
    }

    /// Create and persist a fresh GoblinPay invoice; respond 402 with the
    /// hosted pay page so the client can complete the payment.
    async fn new_invoice(
        &self,
        processor: &Arc<dyn PaymentProcessor>,
        keys: &Keys,
        price_grin: f64,
        price_nanogrin: u64,
    ) -> Response<Body> {
        match processor.get_invoice(keys, price_nanogrin).await {
            Ok(invoice) => {
                if self
                    .repo
                    .create_invoice_record(keys, invoice.clone())
                    .await
                    .is_err()
                {
                    return server_error();
                }
                payment_required(
                    &invoice.payment_hash,
                    &invoice.bolt11,
                    price_grin,
                    price_nanogrin,
                )
            }
            Err(e) => {
                warn!("name authority: goblinpay invoice creation failed: {e:?}");
                server_error()
            }
        }
    }

    fn unregister(&self, name: &str, request: &Request<Body>, ip: &str) -> Response<Body> {
        if !self.allow_write("na-unreg", ip) {
            return rate_limited();
        }
        let name = name.to_lowercase();
        let path = format!("/api/v1/register/{name}");
        let auth_header = request
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let (auth_pubkey, auth_id) = match nip98::verify_nip98(
            auth_header,
            "DELETE",
            &path,
            &[],
            &self.cfg.base_url,
            self.cfg.auth_max_age_secs,
        ) {
            Ok(v) => v,
            Err(msg) => return json_response(StatusCode::UNAUTHORIZED, json!({"error": msg})),
        };
        if !self.auth_event_fresh(&auth_id) {
            return json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "auth event replayed"}),
            );
        }
        // Release is always allowed; releasing is what arms the cooldown.
        match self.lookup(&name) {
            Some(owner) if owner == auth_pubkey => {
                let res = self.db.lock().unwrap().execute(
                    "UPDATE name_claims SET released_at = ?2
                     WHERE name = ?1 AND released_at IS NULL",
                    rusqlite::params![name, unix_time()],
                );
                match res {
                    Ok(_) => {
                        self.record_op("na-namechange", &auth_pubkey);
                        info!("name authority: released {name}");
                        json_response(StatusCode::OK, json!({"name": name, "released": true}))
                    }
                    Err(e) => {
                        error!("name authority: db release failed: {e}");
                        server_error()
                    }
                }
            }
            Some(_) => json_response(StatusCode::FORBIDDEN, json!({"error": "not the owner"})),
            None => json_response(StatusCode::NOT_FOUND, json!({"error": "name not found"})),
        }
    }
}

// ----------------------------------------------------------------------
// Small response helpers
// ----------------------------------------------------------------------

fn strip<'a>(path: &'a str, prefix: &str) -> &'a str {
    path.strip_prefix(prefix).unwrap_or("")
}

fn query_param(request: &Request<Body>, key: &str) -> Option<String> {
    request.uri().query().and_then(|q| {
        q.split('&').find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            if parts.next() == Some(key) {
                parts.next().map(str::to_string)
            } else {
                None
            }
        })
    })
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header("Cache-Control", "no-store")
        .body(Body::from(value.to_string()))
        .expect("response builder")
}

fn text_response(status: StatusCode, text: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Body::from(text))
        .expect("response builder")
}

fn rate_limited() -> Response<Body> {
    json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({"error": "rate_limited"}),
    )
}

fn server_error() -> Response<Body> {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"error": "internal error"}),
    )
}

/// 402 carrying everything a client needs to render or open the GoblinPay
/// pay page, then retry the claim once the payment confirms.
fn payment_required(
    invoice_id: &str,
    pay_url: &str,
    price_grin: f64,
    price_nanogrin: u64,
) -> Response<Body> {
    json_response(
        StatusCode::PAYMENT_REQUIRED,
        json!({
            "error": "payment_required",
            "invoice_id": invoice_id,
            "pay_url": pay_url,
            "price_grin": price_grin,
            "price_nanogrin": price_nanogrin,
        }),
    )
}
