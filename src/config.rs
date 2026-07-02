//! Configuration file and settings management
use crate::payment::Processor;
use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(unused)]
pub struct Info {
    pub relay_url: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub pubkey: Option<String>,
    pub contact: Option<String>,
    pub favicon: Option<String>,
    pub relay_icon: Option<String>,
    pub relay_page: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Database {
    pub data_directory: String,
    pub engine: String,
    pub in_memory: bool,
    pub min_conn: u32,
    pub max_conn: u32,
    pub connection: String,
    pub connection_write: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Grpc {
    pub event_admission_server: Option<String>,
    pub restricts_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Network {
    pub port: u16,
    pub address: String,
    pub remote_ip_header: Option<String>, // retrieve client IP from this HTTP header if present
    pub ping_interval_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Options {
    pub reject_future_seconds: Option<usize>, // if defined, reject any events with a timestamp more than X seconds in the future
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Retention {
    // TODO: implement
    pub max_events: Option<usize>,                // max events
    pub max_bytes: Option<usize>,                 // max size
    pub persist_days: Option<usize>,              // oldest message
    pub whitelist_addresses: Option<Vec<String>>, // whitelisted addresses (never delete)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Limits {
    pub messages_per_sec: Option<u32>, // Artificially slow down event writing to limit disk consumption (averaged over 1 minute)
    pub subscriptions_per_min: Option<u32>, // Artificially slow down request (db query) creation to prevent abuse (averaged over 1 minute)
    pub db_conns_per_client: Option<u32>, // How many concurrent database queries (not subscriptions) may a client have?
    pub max_blocking_threads: usize,
    pub max_event_bytes: Option<usize>, // Maximum size of an EVENT message
    pub max_ws_message_bytes: Option<usize>,
    pub max_ws_frame_bytes: Option<usize>,
    pub broadcast_buffer: usize, // events to buffer for subscribers (prevents slow readers from consuming memory)
    pub event_persist_buffer: usize, // events to buffer for database commits (block senders if database writes are too slow)
    pub event_kind_blacklist: Option<Vec<u64>>,
    pub event_kind_allowlist: Option<Vec<u64>>,
    pub limit_scrapers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Authorization {
    pub pubkey_whitelist: Option<Vec<String>>, // If present, only allow these pubkeys to publish events
    pub nip42_auth: bool,                      // if true enables NIP-42 authentication
    pub nip42_dms: bool, // if true send DMs only to their authenticated recipients
    pub require_auth_to_write: bool, // if true (with nip42_auth), only authenticated clients may publish
}

/// GoblinPay: the Grin payment server used for paid names and paid writes
/// (Floonet addition). One place to configure it; both the built-in name
/// authority and the pay-to-relay admission use these values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct GoblinPay {
    /// Paid mode: "off" (everything free), "name" (claiming a name at the
    /// built-in name authority requires a confirmed payment), or "write"
    /// (publishing events requires a paid admission).
    pub pay_mode: String,
    /// Base URL of the GoblinPay server, e.g. `https://pay.example.com`.
    pub url: String,
    /// GoblinPay API token (`GP_API_TOKEN`); grants invoice create/read.
    pub api_token: String,
    /// Price of a name in GRIN when `pay_mode = "name"`.
    pub name_price_grin: f64,
    /// Price of relay admission in GRIN when `pay_mode = "write"`.
    pub admission_price_grin: f64,
}

impl GoblinPay {
    #[must_use]
    pub fn name_price_nanogrin(&self) -> u64 {
        grin_to_nanogrin(self.name_price_grin)
    }

    #[must_use]
    pub fn admission_price_nanogrin(&self) -> u64 {
        grin_to_nanogrin(self.admission_price_grin)
    }
}

/// 1 GRIN = 1_000_000_000 nanogrin.
#[must_use]
pub fn grin_to_nanogrin(grin: f64) -> u64 {
    (grin * 1_000_000_000.0).round().max(0.0) as u64
}

/// Built-in name authority (the goblin-nip05d capability), served
/// in-process on the relay's own HTTP listener (Floonet addition).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct NameAuthority {
    pub enabled: bool,
    /// Bare host the names live under, e.g. `example.com` (the `@domain`
    /// part of `name@domain`).
    pub domain: String,
    /// Public base URL clients reach, e.g. `https://example.com`.
    /// LOAD-BEARING: NIP-98 auth events are verified against
    /// `<base_url><path>`, so this must be exactly what clients use.
    pub base_url: String,
    /// Relays advertised in `/.well-known/nostr.json`. Unset means
    /// "advertise this relay" (`info.relay_url`).
    pub relays: Option<Vec<String>>,
    /// Name length bounds in characters.
    pub name_min: usize,
    pub name_max: usize,
    /// Seconds a key must wait to claim a new name after releasing one.
    pub name_change_cooldown_secs: u64,
    /// Max age (seconds) of an accepted NIP-98 auth event.
    pub auth_max_age_secs: i64,
    /// Read endpoints: requests per IP per window.
    pub read_rate_max: usize,
    pub read_rate_window_secs: u64,
    /// Write endpoints (register/release): requests per IP per window.
    pub write_rate_max: usize,
    pub write_rate_window_secs: u64,
    /// Optional file of extra reserved names (one per line, # comments).
    pub reserved_file: Option<String>,
}

/// The co-located mixnet exit (Floonet addition): when enabled, the relay
/// supervises a bundled `floonet-mixexit` process so wallets can reach
/// this relay over the mixnet without public DNS on the payment path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct MixnetExit {
    pub enabled: bool,
    /// Path to the bundled floonet-mixexit binary.
    pub binary: String,
    /// Data dir for the persistent mixnet identity. The exit's stable
    /// mixnet address is written to `<data_dir>/nym_address.txt`.
    pub data_dir: String,
    /// Upstream host:port the exit pipes every stream to. Empty means this
    /// relay's own listener (`127.0.0.1:<network.port>`). Point it at your
    /// public TLS endpoint (e.g. `relay.example.com:443`) so wallets see
    /// the same certificate through the mixnet.
    pub upstream: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct PayToRelay {
    pub enabled: bool,
    pub admission_cost: u64, // Cost to have pubkey whitelisted
    pub cost_per_event: u64, // Cost author to pay per event
    pub node_url: String,
    pub api_secret: String,
    pub terms_message: String,
    pub sign_ups: bool,       // allow new users to sign up to relay
    pub direct_message: bool, // Send direct message to user with invoice and terms
    pub secret_key: Option<String>,
    pub processor: Processor,
    pub rune_path: Option<String>, // To access clightning API
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Diagnostics {
    pub tracing: bool, // enables tokio console-subscriber
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum VerifiedUsersMode {
    Enabled,
    Passive,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct VerifiedUsers {
    pub mode: VerifiedUsersMode, // Mode of operation: "enabled" (enforce) or "passive" (check only). If none, this is simply disabled.
    pub domain_whitelist: Option<Vec<String>>, // If present, only allow verified users from these domains can publish events
    pub domain_blacklist: Option<Vec<String>>, // If present, allow all verified users from any domain except these
    pub verify_expiration: Option<String>, // how long a verification is cached for before no longer being used
    pub verify_update_frequency: Option<String>, // how often to attempt to update verification
    pub verify_expiration_duration: Option<Duration>, // internal result of parsing verify_expiration
    pub verify_update_frequency_duration: Option<Duration>, // internal result of parsing verify_update_frequency
    pub max_consecutive_failures: usize, // maximum number of verification failures in a row, before ceasing future checks
}

impl VerifiedUsers {
    pub fn init(&mut self) {
        self.verify_expiration_duration = self.verify_expiration_duration();
        self.verify_update_frequency_duration = self.verify_update_duration();
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.mode == VerifiedUsersMode::Enabled
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.mode == VerifiedUsersMode::Enabled || self.mode == VerifiedUsersMode::Passive
    }

    #[must_use]
    pub fn is_passive(&self) -> bool {
        self.mode == VerifiedUsersMode::Passive
    }

    #[must_use]
    pub fn verify_expiration_duration(&self) -> Option<Duration> {
        self.verify_expiration
            .as_ref()
            .and_then(|x| parse_duration::parse(x).ok())
    }

    #[must_use]
    pub fn verify_update_duration(&self) -> Option<Duration> {
        self.verify_update_frequency
            .as_ref()
            .and_then(|x| parse_duration::parse(x).ok())
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.verify_expiration_duration().is_some() && self.verify_update_duration().is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Logging {
    pub folder_path: Option<String>,
    pub file_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub info: Info,
    pub diagnostics: Diagnostics,
    pub database: Database,
    pub grpc: Grpc,
    pub network: Network,
    pub limits: Limits,
    pub authorization: Authorization,
    pub pay_to_relay: PayToRelay,
    pub goblinpay: GoblinPay,
    pub name_authority: NameAuthority,
    pub exit: MixnetExit,
    pub verified_users: VerifiedUsers,
    pub retention: Retention,
    pub options: Options,
    pub logging: Logging,
}

impl Settings {
    pub fn new(config_file_name: &Option<String>) -> Result<Self, ConfigError> {
        let default_settings = Self::default();
        // attempt to construct settings with file
        let from_file = Self::new_from_default(&default_settings, config_file_name);
        match from_file {
            Err(e) => {
                // pass up the parse error if the config file was specified,
                // otherwise use the default config (with a warning).
                if config_file_name.is_some() {
                    Err(e)
                } else {
                    eprintln!("Error reading config file ({:?})", e);
                    eprintln!("WARNING: Default configuration settings will be used");
                    Ok(default_settings)
                }
            }
            ok => ok,
        }
    }

    fn new_from_default(
        default: &Settings,
        config_file_name: &Option<String>,
    ) -> Result<Self, ConfigError> {
        let default_config_file_name = "config.toml".to_string();
        let config: &String = match config_file_name {
            Some(value) => value,
            None => &default_config_file_name,
        };
        let builder = Config::builder();
        let config: Config = builder
            // use defaults
            .add_source(Config::try_from(default)?)
            // override with file contents
            .add_source(File::with_name(config))
            .build()?;
        let mut settings: Settings = config.try_deserialize()?;
        // Floonet env overrides, so paid mode can be flipped without
        // editing the config file (secrets can stay out of it entirely).
        if let Ok(v) = std::env::var("FLOONET_PAY_MODE") {
            settings.goblinpay.pay_mode = v;
        }
        if let Ok(v) = std::env::var("FLOONET_GOBLINPAY_URL") {
            settings.goblinpay.url = v;
        }
        if let Ok(v) = std::env::var("FLOONET_GOBLINPAY_TOKEN") {
            settings.goblinpay.api_token = v;
        }
        if let Ok(v) = std::env::var("FLOONET_NAME_PRICE_GRIN") {
            if let Ok(price) = v.parse::<f64>() {
                settings.goblinpay.name_price_grin = price;
            }
        }
        // Validate + apply the Floonet paid mode.
        match settings.goblinpay.pay_mode.as_str() {
            "off" => {}
            "name" | "write" => {
                assert!(
                    !settings.goblinpay.url.is_empty(),
                    "goblinpay.url must be set when goblinpay.pay_mode is enabled"
                );
                assert!(
                    !settings.goblinpay.api_token.is_empty(),
                    "goblinpay.api_token must be set when goblinpay.pay_mode is enabled"
                );
                if settings.goblinpay.pay_mode == "write" {
                    // "write" rides the upstream pay-to-relay admission,
                    // with GoblinPay as the payment processor.
                    settings.pay_to_relay.enabled = true;
                    settings.pay_to_relay.processor = Processor::GoblinPay;
                    settings.pay_to_relay.node_url = settings.goblinpay.url.clone();
                    settings.pay_to_relay.api_secret = settings.goblinpay.api_token.clone();
                    settings.pay_to_relay.admission_cost =
                        settings.goblinpay.admission_price_nanogrin();
                    if settings.pay_to_relay.terms_message.is_empty() {
                        settings.pay_to_relay.terms_message =
                            "Use this relay lawfully and without abuse.".to_string();
                    }
                }
            }
            other => panic!("goblinpay.pay_mode must be off, name, or write (got `{other}`)"),
        }
        if settings.name_authority.enabled {
            assert!(
                !settings.name_authority.domain.is_empty(),
                "name_authority.domain must be set"
            );
            let base = &settings.name_authority.base_url;
            assert!(
                base.starts_with("https://")
                    || base.starts_with("http://127.0.0.1")
                    || base.starts_with("http://localhost"),
                "name_authority.base_url must be https:// (http only for localhost testing)"
            );
            assert!(
                settings.name_authority.name_min > 0
                    && settings.name_authority.name_min <= settings.name_authority.name_max,
                "invalid name_authority name length bounds"
            );
            assert!(
                settings.database.engine == "sqlite",
                "the built-in name authority requires the sqlite database engine"
            );
        }
        // ensure connection pool size is logical
        assert!(
            settings.database.min_conn <= settings.database.max_conn,
            "Database min_conn setting ({}) cannot exceed max_conn ({})",
            settings.database.min_conn,
            settings.database.max_conn
        );
        // ensure durations parse
        assert!(
            settings.verified_users.is_valid(),
            "VerifiedUsers time settings could not be parsed"
        );
        // initialize durations for verified users
        settings.verified_users.init();

        // Validate pay to relay settings
        if settings.pay_to_relay.enabled {
            if settings.pay_to_relay.processor == Processor::ClnRest {
                assert!(settings
                    .pay_to_relay
                    .rune_path
                    .as_ref()
                    .is_some_and(|path| path != "<rune path>"));
            } else if settings.pay_to_relay.processor == Processor::LNBits {
                assert_ne!(settings.pay_to_relay.api_secret, "");
            }
            // Should check that url is valid
            assert_ne!(settings.pay_to_relay.node_url, "");
            assert_ne!(settings.pay_to_relay.terms_message, "");

            if settings.pay_to_relay.direct_message {
                assert!(settings
                    .pay_to_relay
                    .secret_key
                    .as_ref()
                    .is_some_and(|key| key != "<nostr nsec>"));
            }
        }

        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            info: Info {
                relay_url: None,
                name: Some("floonet-rs-relay".to_owned()),
                description: Some(
                    "A Floonet relay for the Grin community Nostr network.".to_owned(),
                ),
                pubkey: None,
                contact: None,
                favicon: None,
                relay_icon: None,
                relay_page: None,
            },
            diagnostics: Diagnostics { tracing: false },
            database: Database {
                data_directory: ".".to_owned(),
                engine: "sqlite".to_owned(),
                in_memory: false,
                min_conn: 4,
                max_conn: 8,
                connection: "".to_owned(),
                connection_write: None,
            },
            grpc: Grpc {
                event_admission_server: None,
                restricts_write: false,
            },
            network: Network {
                port: 8080,
                ping_interval_seconds: 300,
                address: "0.0.0.0".to_owned(),
                remote_ip_header: None,
            },
            limits: Limits {
                messages_per_sec: None,
                subscriptions_per_min: None,
                db_conns_per_client: None,
                max_blocking_threads: 16,
                max_event_bytes: Some(2 << 17),      // 128K
                max_ws_message_bytes: Some(2 << 17), // 128K
                max_ws_frame_bytes: Some(2 << 17),   // 128K
                broadcast_buffer: 16384,
                event_persist_buffer: 4096,
                event_kind_blacklist: None,
                // Floonet keystone: default-deny kind whitelist.
                event_kind_allowlist: Some(crate::admission::DEFAULT_ALLOWED_KINDS.to_vec()),
                limit_scrapers: false,
            },
            authorization: Authorization {
                pubkey_whitelist: None, // Allow any address to publish
                nip42_auth: false,      // Disable NIP-42 authentication
                nip42_dms: false,       // Send DMs to everybody
                require_auth_to_write: false,
            },
            pay_to_relay: PayToRelay {
                enabled: false,
                admission_cost: 4200,
                cost_per_event: 0,
                terms_message: "".to_string(),
                node_url: "".to_string(),
                api_secret: "".to_string(),
                rune_path: None,
                sign_ups: false,
                direct_message: false,
                secret_key: None,
                processor: Processor::LNBits,
            },
            goblinpay: GoblinPay {
                pay_mode: "off".to_owned(),
                url: String::new(),
                api_token: String::new(),
                name_price_grin: 1.0,
                admission_price_grin: 1.0,
            },
            name_authority: NameAuthority {
                enabled: false,
                domain: String::new(),
                base_url: String::new(),
                relays: None,
                name_min: 3,
                name_max: 20,
                name_change_cooldown_secs: 600,
                auth_max_age_secs: 60,
                read_rate_max: 120,
                read_rate_window_secs: 60,
                write_rate_max: 10,
                write_rate_window_secs: 3600,
                reserved_file: None,
            },
            exit: MixnetExit {
                enabled: false,
                binary: "/usr/local/bin/floonet-mixexit".to_owned(),
                data_dir: "./mixexit-data".to_owned(),
                upstream: String::new(),
            },
            verified_users: VerifiedUsers {
                mode: VerifiedUsersMode::Disabled,
                domain_whitelist: None,
                domain_blacklist: None,
                verify_expiration: Some("1 week".to_owned()),
                verify_update_frequency: Some("1 day".to_owned()),
                verify_expiration_duration: None,
                verify_update_frequency_duration: None,
                max_consecutive_failures: 20,
            },
            retention: Retention {
                max_events: None,          // max events
                max_bytes: None,           // max size
                persist_days: None,        // oldest message
                whitelist_addresses: None, // whitelisted addresses (never delete)
            },
            options: Options {
                reject_future_seconds: None, // Reject events in the future if defined
            },
            logging: Logging {
                folder_path: None,
                file_prefix: None,
            },
        }
    }
}
