//! Co-located mixnet exit supervisor (Floonet addition).
//!
//! When `[exit] enabled = true`, the relay runs the bundled
//! `floonet-mixexit` binary alongside itself and keeps it running. The
//! exit is a scoped pipe: it joins the mixnet as an ordinary unbonded
//! client and forwards every accepted stream to ONE fixed upstream (this
//! relay), never a caller-chosen target, so it is structurally not an
//! open proxy and the operator needs no exit policy.
//!
//! The exit's mixnet identity persists in `exit.data_dir`, so its mixnet
//! address is STABLE across restarts; the binary prints it at startup and
//! writes it to `<data_dir>/nym_address.txt`. Publish that address (for
//! example in the Floonet relay pool `exit` field) so wallets can prefer
//! it and fall back to the public mixnet path when it is down.
//!
//! Wallets run hostname-validated TLS end to end THROUGH the pipe, so the
//! exit only ever sees ciphertext. Point `exit.upstream` at your public
//! TLS endpoint (e.g. `relay.example.com:443`) so the certificate the
//! wallet sees over the mixnet matches the one it pins.

use crate::config::Settings;
use crate::error::{Error, Result};
use std::path::Path;
use std::time::Duration;
use tracing::{error, info, warn};

/// Validate the exit configuration at startup: fail fast on a bad toggle
/// instead of silently running without the exit.
pub fn validate(settings: &Settings) -> Result<()> {
    if !settings.exit.enabled {
        return Ok(());
    }
    if !Path::new(&settings.exit.binary).is_file() {
        let msg = format!(
            "exit.enabled is true but exit.binary `{}` does not exist; \
             install floonet-mixexit or disable the exit",
            settings.exit.binary
        );
        error!("{msg}");
        return Err(Error::CustomError(msg));
    }
    Ok(())
}

/// Spawn the supervision task. Must be called from within the tokio
/// runtime. The child is restarted with a backoff if it exits; it is
/// killed when the relay shuts down (kill-on-drop).
pub fn spawn(settings: &Settings) {
    if !settings.exit.enabled {
        return;
    }
    let binary = settings.exit.binary.clone();
    let data_dir = settings.exit.data_dir.clone();
    let upstream = if settings.exit.upstream.is_empty() {
        format!("127.0.0.1:{}", settings.network.port)
    } else {
        settings.exit.upstream.clone()
    };
    info!(
        "mixnet exit enabled: supervising {} (upstream {}, identity in {})",
        binary, upstream, data_dir
    );
    tokio::spawn(async move {
        loop {
            let child = tokio::process::Command::new(&binary)
                .env("FLOONET_MIXEXIT_DIR", &data_dir)
                .env("FLOONET_EXIT_UPSTREAM", &upstream)
                .kill_on_drop(true)
                .spawn();
            match child {
                Ok(mut child) => match child.wait().await {
                    Ok(status) => {
                        warn!("mixnet exit process ended ({status}); restarting in 10s");
                    }
                    Err(e) => {
                        warn!("mixnet exit process wait failed ({e}); restarting in 10s");
                    }
                },
                Err(e) => {
                    error!("mixnet exit failed to start ({e}); retrying in 10s");
                }
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
}
