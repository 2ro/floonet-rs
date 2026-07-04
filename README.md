# floonet-rs

A hardened [Floonet](https://floonet.dev) relay for the Grin community
Nostr network, forked from
[nostr-rs-relay](https://git.sr.ht/~gheartsfield/nostr-rs-relay).

Floonet is a network of Nostr relays for the Grin community: anyone can
run one, and anyone can run a name authority on it so people can claim
(and optionally pay for) a `name@domain` identity. floonet-rs keeps the
upstream relay core intact and adds three configurable, modular features:

* An **event kind whitelist** (the keystone): default-deny admission.
  The relay accepts ONLY the kinds it is configured to allow and rejects
  everything else. The shipped set is
  `0, 3, 5, 13, 1059, 10002, 10050, 27235`.
* **Authentication**: NIP-42, with optional require-auth-to-write and an
  author whitelist.
* A **built-in name authority**: `name@domain` NIP-05 identities with
  NIP-98 authenticated self-service registration, served in-process on
  the relay's own subdomain — no separate hostname to run. Optionally
  paid in GRIN through GoblinPay.

The public relay metadata stays neutral on purpose: the NIP-11 document
and landing page never mention payments. The relay only ever sees opaque
gift-wrapped ciphertext, so payment wording would be both inaccurate and
an operational liability.

## Deploy

Pick your comfort level. All three paths end with the same relay.

### 1. Docker Compose (recommended)

Brings up the relay plus a Caddy TLS proxy in one command:

```sh
cp config.toml my-config.toml
# edit my-config.toml: info.relay_url, and [network] address = "0.0.0.0"
echo 'FLOONET_DOMAIN=relay.example.com' > .env
docker compose up -d
```

The relay container is non-root with a read-only root filesystem; Caddy
obtains certificates automatically and forwards the real client IP.

### 2. Binary + installer + systemd

From an unpacked release archive (or a source checkout after building),
the installer drops the binary, a default config, and a hardened
systemd unit; no toolchain needed at install time:

```sh
sudo sh deploy/install.sh
sudo $EDITOR /etc/floonet-rs/config.toml   # set info.relay_url
sudo systemctl start floonet-rs
```

Put a TLS proxy in front (see `deploy/Caddyfile`). The unit runs as a
dynamic unprivileged user with a read-only system view
(`ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`,
syscall filtering); only `/var/lib/floonet-rs` is writable.

### 3. Source build

```sh
cargo build --release
./target/release/floonet-rs --config config.toml --db .
```

Requires a protobuf compiler (`protoc`) for the gRPC extension point.

## The whitelist (keystone)

```toml
[limits]
event_kind_allowlist = [0, 3, 5, 13, 1059, 10002, 10050, 27235]
```

Fail-closed semantics, enforced in the write path before anything is
queued for persistence:

* The listed kinds are accepted; **everything else is rejected** with an
  `OK false` / `blocked:` message.
* Removing the line keeps the built-in Floonet set. There is no
  allow-all: an empty list denies everything.
* To add a kind, add it to the list and restart. Never narrow the list
  below what your users' wallets already depend on.

## Authentication (NIP-42)

```toml
[authorization]
nip42_auth = true             # send AUTH challenges
require_auth_to_write = true  # refuse writes until the client AUTHs
nip42_dms = true              # gift wraps only to their recipients
#pubkey_whitelist = ["<hex>"] # restrict authors entirely
```

Unauthenticated writes are refused with an `auth-required:` prefixed OK
message, so compliant clients authenticate and resend.

## Name authority

Enable the built-in authority to serve `name@yourdomain` identities:

```toml
[name_authority]
enabled = true
domain = "example.com"
base_url = "https://example.com"   # must match what clients reach
```

Endpoints, all on the relay's own listener:

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/nostr.json?name=<name>` | NIP-05 resolution |
| `POST /api/v1/register` | claim a name (NIP-98 auth) |
| `DELETE /api/v1/register/{name}` | release a name (NIP-98 auth) |
| `GET /api/v1/name/{name}` | availability |
| `GET /api/v1/profile/{name}` | name to pubkey |
| `GET /api/v1/by-pubkey/{pubkey}` | reverse lookup |
| `GET /api/v1/health` | liveness |

Rules carried over from goblin-nip05d: lowercase `[a-z0-9._-]` names
(3 to 20 characters, alphanumeric at both ends), a built-in reserved
list plus your own domain labels with look-alike folding (`g0blin`
cannot impersonate `goblin`), one active name per key enforced by the
database, NIP-98 verification with a bounded replay window, per-IP rate
limits, and a release-armed rename cooldown. Claims live in the relay's
own SQLite database (`name_claims` table).

## Charge GRIN for your relay

Paid use is one switch plus a price. Point the relay at your GoblinPay
server and pick a mode:

```toml
[goblinpay]
pay_mode = "name"                  # or "write", or "off"
url = "https://pay.example.com"
api_token = "<GP_API_TOKEN>"
name_price_grin = 1.0
```

Or keep secrets out of the file entirely and use the environment:
`FLOONET_PAY_MODE`, `FLOONET_GOBLINPAY_URL`, `FLOONET_GOBLINPAY_TOKEN`,
`FLOONET_NAME_PRICE_GRIN`.

* **`pay_mode = "name"`**: claiming a name answers
  `402 {"error":"payment_required","pay_url":...}` with a hosted
  GoblinPay page (GoblinPay, manual slatepack, or a `grin1` address if
  the operator enabled that method). Once the payment confirms on chain,
  the same register call succeeds. Clients have everything they need to
  send the user straight to the pay page and retry.
* **`pay_mode = "write"`**: publishing requires a paid admission; the
  relay reuses its pay-to-relay account model with GoblinPay as the
  payment processor.
* A GoblinPay webhook may POST `{"invoice_id": ...}` to `/goblinpay` to
  speed things up; the relay always re-verifies the invoice with the
  GoblinPay server before admitting anything, so a forged webhook cannot
  fake a payment.

Payments admit the pubkey, not the request: after one confirmed payment
a key can claim, release, and re-claim its single name without paying
again (the rename cooldown still applies).

Prices are plain config values; edit and restart to change them. The
public relay metadata stays payment-free regardless of mode.

## Transport privacy (Tor)

This relay needs no privacy component of its own. Wallets connect to it
over Tor: the client opens a Tor circuit and reaches the relay's
ordinary clearnet endpoint through a Tor exit, so the relay never sees
the user's real IP. Tor hides the user's network location; the kind
whitelist and gift-wrapped (kind 1059) payloads hide everything else
(content, sender, timing) from the relay itself.

An operator who wants to remove the Tor-exit hop entirely can front the
relay with a Tor onion service: run the system `tor` daemon with a
`HiddenServiceDir` and a `HiddenServicePort` pointed at the relay's
local listener (`127.0.0.1:<network.port>`), then publish the resulting
`.onion` address. That is a deploy-layer addition (a `torrc` stanza), not
a build of this crate. The relay binary is unchanged either way.

## Extending: policies and paid resources

Admission is a small ordered pipeline in `src/admission.rs`. Each check
implements one trait:

```rust
pub trait AdmissionPolicy: Send + Sync {
    fn check(&self, event: &Event, authed_pubkey: Option<&str>) -> Decision;
}
```

To add a policy (a paid gate, a spam filter, a tag rule), implement the
trait and append it in `Admission::from_settings`; the first denial
wins. To add a kind, edit the config; no code change needed. The gRPC
`event_admission_server` extension point from upstream also remains
available for out-of-process policies.

Paid uses follow the same pattern as names: quote a price, hand the
client a GoblinPay pay page, verify the confirmed invoice, then grant
the resource. Names are the first paid resource; **paid media storage
for GRIN** (NIP-96 HTTP file storage or Blossom content-addressed
blobs, advertised with a kind 10063 server list, priced per upload or
per MB) is the designed-for next example: the same
`402 pay_url -> confirm -> grant` gate applied to an upload endpoint.

## Operational notes

* **Reverse proxy**: terminate TLS at Caddy or nginx and forward
  `X-Real-IP` (`remote_ip_header` in the config). All per-IP rate
  limiting keys off it.
* **Event size**: keep `max_event_bytes` at its default (256 KB) or
  larger; gift-wrapped payloads can be big.
* **Database**: SQLite by default; the schema migrates automatically at
  startup (this fork adds `name_claims` at version 19). The name
  authority requires the sqlite engine; postgres remains available for
  the plain relay.
* **Secrets**: nothing in this repository; the GoblinPay token comes
  from the config file (0600) or the environment.
* **Multiple identities, one wallet**: a Goblin wallet can hold several
  Nostr identities. If you pay for a name and want to keep it, load the
  same wallet and switch to (or add) that npub; different identities
  share one wallet.

Upstream documentation for the inherited features lives in `docs/`
(database maintenance, gRPC extensions, reverse proxies, and more) and
in `docs/upstream/README.md`.

## Development

```sh
cargo build --release       # build the relay
cargo test                  # unit + integration tests
```

The integration tests stand up real relays on loopback and cover the
whitelist end to end (allowed kind accepted, disallowed kind rejected),
the name authority round trip (register, resolve, reverse lookup,
conflicts, reserved names, release, cooldown), the paid-name flow
against a stub GoblinPay server, and the payment-free NIP-11 rule.

## License

MIT, same as upstream. The upstream relay is by Greg Heartsfield and
contributors; the Floonet additions are by the Floonet developers.

🤖 Built with AI pair-programming assistance (Claude)
