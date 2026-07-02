#!/bin/sh
# floonet-rs installer: drops the binary, config, and hardened systemd
# unit. No toolchain needed when run from an unpacked release archive.
#
# Usage:
#   sudo sh deploy/install.sh
#
# Looks for the binaries next to this script's parent directory in this
# order: ./floonet-rs (release archive layout), then
# target/release/floonet-rs (source build layout). The optional
# floonet-mixexit binary is installed the same way when present.
#
# Idempotent: re-running upgrades the binaries and unit but never
# overwrites an existing /etc/floonet-rs/config.toml.

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root (sudo sh deploy/install.sh)" >&2
    exit 1
fi

here="$(cd "$(dirname "$0")/.." && pwd)"

find_binary() {
    name="$1"
    for candidate in "$here/$name" "$here/target/release/$name"; do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

relay_bin="$(find_binary floonet-rs)" || {
    echo "error: floonet-rs binary not found; build it first (cargo build --release)" >&2
    exit 1
}

echo "installing $relay_bin -> /usr/local/bin/floonet-rs"
install -m0755 "$relay_bin" /usr/local/bin/floonet-rs

if exit_bin="$(find_binary floonet-mixexit)"; then
    echo "installing $exit_bin -> /usr/local/bin/floonet-mixexit"
    install -m0755 "$exit_bin" /usr/local/bin/floonet-mixexit
else
    echo "note: floonet-mixexit binary not found; skipping (the mixnet exit"
    echo "      toggle needs it; see mixexit/README section in README.md)"
fi

install -d -m0755 /etc/floonet-rs
if [ ! -f /etc/floonet-rs/config.toml ]; then
    echo "installing default config -> /etc/floonet-rs/config.toml"
    install -m0600 "$here/config.toml" /etc/floonet-rs/config.toml
    echo ">>> EDIT /etc/floonet-rs/config.toml: set info.relay_url at minimum."
else
    echo "keeping existing /etc/floonet-rs/config.toml"
fi

echo "installing systemd unit -> /etc/systemd/system/floonet-rs.service"
install -m0644 "$here/deploy/floonet-rs.service" /etc/systemd/system/floonet-rs.service
systemctl daemon-reload
systemctl enable floonet-rs

echo
echo "done. next steps:"
echo "  1. edit /etc/floonet-rs/config.toml (relay_url, and optionally"
echo "     the name authority, paid mode, and mixnet exit sections)"
echo "  2. put a TLS proxy in front (see deploy/Caddyfile)"
echo "  3. systemctl start floonet-rs && journalctl -fu floonet-rs"
