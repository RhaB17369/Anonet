# anonet

A Rust orchestration layer built on top of Tor (via [`arti-client`](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's own Rust implementation). anonet does not reimplement Tor's cryptography or routing — it embeds a real Tor client and adds the operational layer around it: a SOCKS5 front end, per-app circuit isolation, bridge/pluggable-transport failover, DNS-leak prevention, nftables kill switches, and a live dashboard.

## What anonet actually is (read this first)

**anonet is a SOCKS5 proxy, not a VPN.** Launching it starts a proxy server listening on `127.0.0.1:9450`. By itself, this does **not** route any of your machine's traffic through Tor — nothing is intercepted automatically. Only applications explicitly configured to use that SOCKS5 proxy get anonymized.

There are three ways to actually anonymize traffic with anonet, in increasing order of scope:

1. **Configure one application** to use the SOCKS5 proxy at `127.0.0.1:9450` (e.g. Firefox's network settings, `curl --socks5-hostname`, etc.). Only that app's traffic goes through Tor. This is the safest and most common option.
2. **Full anonymization** (the `t` key in the dashboard, or `anonet killswitch` combined with it): supervises a real system `tor` process configured with `TransPort`/`DNSPort`, redirects **all** TCP and DNS traffic on the machine to it via nftables, and enables the radical kill switch as a fail-safe. This routes the entire machine through Tor automatically, with no per-app configuration. It needs root.
3. **Kill switches alone** (`k`/`d` in the dashboard, or `anonet killswitch`): firewall rules that block traffic rather than route it. Useful as a safety net around option 1 or 2, not a way to anonymize traffic by themselves.

If you just launch `anonet` and check your IP in a normal browser with no proxy configured, it will not change — that is expected, not a bug.

## Quick start

```
cargo build --release
./target/release/anonet
```

Launching `anonet` with no arguments boots straight into the live dashboard (like `htop`/`btop`) with all defaults. `anonet run ...` is the same thing spelled out explicitly. Nothing needs root **except** the kill switches and full anonymization (both use nftables).

To point an application at the proxy:

```
curl --socks5-hostname 127.0.0.1:9450 https://example.com
```

Use `--socks5-hostname` (not `--socks5`) so DNS resolution happens through Tor, not locally — anonet's leak policy rejects raw-IP CONNECT requests by default specifically to catch and prevent this class of leak.

## CLI options (`anonet` / `anonet run`)

| Flag | Default | What it does |
|---|---|---|
| `--bind <ADDR>` | `127.0.0.1:9450` | Where the SOCKS5 proxy listens. |
| `--bridge <LINE>` | none | A torrc-style `Bridge ...` line (see [Bridges](#bridges-what-they-are-and-when-you-need-them) below). Repeatable; tried in order at startup until one passes its health check. More can be added live from the dashboard with `a`. If the line names a known pluggable transport (currently `obfs4`), its binary is auto-detected on disk — you don't need `--pt` for it. |
| `--pt <PROTOCOL=PATH>` | none | Registers a pluggable-transport binary at an explicit path, e.g. `obfs4=/usr/bin/obfs4proxy`. Only needed to override auto-detection (non-standard install path) or for a transport anonet doesn't know how to locate on its own. Repeatable. |
| `--bridge-timeout-secs <N>` | `30` | How long to wait for a bridge health check before trying the next candidate. |
| `--dns-shim <ADDR>` | none | Also runs a DNS-over-UDP resolver on this address, resolving every query via Tor. For apps that insist on resolving names themselves instead of using SOCKS5 hostname CONNECT. Can also be started/stopped live with `n`. |
| `--bridge-check-interval-secs <N>` | `60` | How often the background monitor re-checks the currently active bridge. |
| `--bridge-failure-threshold <N>` | `3` | Consecutive failed health checks before the monitor searches for a replacement bridge. |
| `--headless` | off | Skips the dashboard and just logs to stdout — for scripts, systemd units, or anywhere nothing will be watching a terminal. The dashboard is the default. |

### `anonet killswitch`

Manages the nftables kill switches directly from the command line (root required). See [Kill switches](#kill-switches) below for what each mode actually does.

```
anonet killswitch enable --mode scoped --protect-uid <UID> [--ttl-secs N]
anonet killswitch enable --mode radical [--ttl-secs N]   # defaults to a 300s TTL if none given
anonet killswitch disable --mode scoped|radical
anonet killswitch status
```

### `anonet status`

Reports a running `anonet run` instance's live state — SOCKS connections, active bridge, DNS shim, full-anonymization status, last error — without opening the dashboard or parsing the log file. For scripts and systemd health checks (`--headless` has no other way to introspect a running instance).

```
$ anonet status
socks_listening: 127.0.0.1:9450
socks_connections_active: 0
socks_connections_total: 3
dns_shim: stopped
active_bridge: none (direct connection)
bridge_candidates: 0
consecutive_failures: 0
total_bridge_switches: 0
full_anonymization: stopped
last_error: none
```

Works against any `anonet run` instance owned by the same user (headless or dashboard) via a Unix socket at `$XDG_DATA_HOME/anonet/anonet.sock`. Fails with a clear message if no instance is running.

## The dashboard

Everything the process can do is reachable live from the dashboard, not just at launch. The help line at the bottom always shows what's available in the current mode.

| Key | Action |
|---|---|
| `q` / `Esc` | Quit. |
| `a` | Type in a new bridge line and try it live. If it passes its health check, it's activated immediately — same mechanism as automatic failover, triggered manually. |
| `c` | Force an immediate health check of the active bridge instead of waiting out the check interval. |
| `n` | Toggle the DNS shim: stops it if running, otherwise asks for a bind address and starts it. |
| `k` | Enable a kill switch. Scoped asks for a UID; radical asks for a `y` confirmation (see below for why). |
| `d` | Disable a kill switch. No confirmation needed — turning one off is always the safe direction. |
| `t` | Toggle full system-wide anonymization (see above). Enabling asks for confirmation, since it's the most disruptive action available; disabling is one key. |

### Panels

- **Services** — SOCKS5 bind address and live connection count, DNS shim status, number of bridges configured, full-anonymization status.
- **Bridge / Circuit** — health of the currently active bridge: consecutive failures, total failovers, last check/switch time, and a latency sparkline.
- **Bridge candidates** — every configured bridge's last known status, not just the active one (`*` marks the active one).
- **Isolation buckets** — active per-app circuit isolation identities (see [Stream isolation](#stream-isolation)), with use count and age. Populated by SOCKS5 connections, not the transparent-proxy path.
- **Kill switches** — live status of both switches (`unknown (needs root)` if anonet isn't running as root).
- **Recent log** — tail of the log file (dashboard mode redirects logs to `~/.local/share/anonet/anonet.log` since the dashboard itself uses stdout).
- **Live traffic** — real connections observed via the supervised tor's ControlPort `STREAM` events. Only populated while full anonymization (`t`) is running, since that's the only path where a real `tor` process (not anonet itself) handles the connections.
- **Status line** (bottom) — transient messages, or a persistent red `ERROR: ...` banner if a background action (e.g. `t` failing without root) failed, until the next relevant retry clears it.

## Bridges: what they are, and when you need them

A bridge is **not** a server you need to find, host, or secure yourself. It's an unlisted Tor entry point, handed out by the Tor Project or volunteers specifically so people can reach Tor when it's being actively blocked.

**You almost certainly don't need one.** Bridges exist for exactly one purpose: getting around a network that's actively blocking connections to public Tor relays (state censorship, a restrictive corporate firewall, etc.). If your normal internet connection isn't censored, direct mode — the default, no bridge required — already works and is exactly what you want.

To get a real bridge line: Tor Browser's Settings → Connection → Bridges → "Request a new bridge" or "Select a built-in bridge", or <https://bridges.torproject.org>. A bridge line looks like:

```
Bridge obfs4 <IP>:<PORT> <FINGERPRINT> cert=<...> iat-mode=0
```

Using an `obfs4` bridge requires the `obfs4proxy` (or `lyrebird`) binary to be installed — anonet auto-detects it on `$PATH` and in common install locations, both for `--bridge` at launch and for a bridge added live with `a`. If it can't find one, it fails with a one-line message naming the install command for your distro instead of a deep Arti error; use `--pt obfs4=/path/to/obfs4proxy` only if it's installed somewhere non-standard.

## Kill switches

Two independent nftables-based switches, each in its own table so enabling/disabling one never affects the other or any pre-existing firewall rules:

- **Scoped** (`anonet_ks_scoped`): confines one specific UID to loopback only. Meant to force one particular app (that you separately point at the SOCKS5 proxy, or run as a dedicated user) to have no other network access — protects that one app from leaking via a side channel that bypasses the proxy.
- **Radical** (`anonet_ks_system`): drops all non-loopback egress on the machine except anonet's own UID. A Whonix-gateway-style "nothing leaves except through Tor" mode. This is the fail-safe used by full anonymization (`t`), and can also be enabled standalone. It will break every other app's network access while enabled — that's the point, not a bug. Defaults to a 300s auto-revert TTL so a forgotten radical kill switch can't permanently strand the machine offline.

Neither is applied automatically by `anonet run`; both are explicit, deliberate actions (`anonet killswitch enable ...`, or `k`/`d` in the dashboard).

## Full anonymization (`t`)

Combines three pieces to route the entire machine through Tor with no per-app configuration:

1. A supervised, real `tor` process (not `arti-client`) with `TransPort`/`DNSPort` enabled — Tor's own native transparent-proxy support, the same mechanism tools like Parrot's `anonsurf` use. anonet doesn't reimplement transparent interception itself.
2. nftables NAT rules redirecting all TCP and UDP/53 traffic to those ports, for every UID except anonet's own. Loopback and private ranges (IPv4 RFC1918 and their IPv6 equivalents — `::1`, `fc00::/7`, `fe80::/10`) and port 22 (SSH) are excluded so LAN traffic and SSH sessions keep working.
3. The radical kill switch as a fail-safe for anything that isn't TCP/DNS or somehow doesn't get redirected.

Requires root. The "Live traffic" panel shows real connections via the supervised tor's ControlPort once this is running.

## Stream isolation

Each SOCKS5 connection is isolated into a circuit-sharing "bucket" keyed by the SOCKS5 username it authenticates with (any username works — it's used as an isolation key, not a real credential, the same trick Tor's own `IsolateSOCKSAuth` uses). Connections with the same identity may share a circuit; different identities never do. Buckets rotate to a fresh circuit automatically after 10 minutes or 200 uses, whichever comes first.

```
curl --socks5-hostname --proxy-user alice:x 127.0.0.1:9450 https://example.com   # bucket "alice"
curl --socks5-hostname --proxy-user bob:x   127.0.0.1:9450 https://example.com   # bucket "bob", different circuit
```

Connections with no auth all share one `default` bucket.

## DNS-leak prevention

The SOCKS5 front end rejects CONNECT requests that name a raw IP address by default — the only way such a request can exist is if something upstream already resolved the hostname outside Tor, which is the leak itself. Always use `--socks5-hostname` (curl) or your app's equivalent "remote DNS" setting.

For apps that resolve names themselves and can't be pointed at the SOCKS5 proxy for that, the DNS shim (`--dns-shim <addr>` or `n` in the dashboard) resolves A/AAAA queries via Tor's exit relay instead of the system resolver.

## Installing as a system service

`packaging/install.sh` builds the release binary and installs it to `/usr/local/bin/anonet` (asks for `sudo`), with an optional prompt to also install `packaging/anonet.service` for running `anonet run --headless` under systemd:

```
./packaging/install.sh
# ...then, if you installed the unit:
sudo systemctl enable --now anonet
```

The unit runs as root by default (needed for kill switches / full anonymization); if this instance is only ever a plain SOCKS5 proxy, edit the unit to run as an unprivileged user instead — see the comments in `packaging/anonet.service`.

## Logs

Dashboard mode writes logs to `~/.local/share/anonet/anonet.log` (stdout is the dashboard itself). The log is rotated once, at the start of each launch, if it's grown past 10MB — the previous file is kept as `anonet.log.1`. `--headless` mode logs straight to stdout instead and isn't rotated (redirect it through your own log management, e.g. systemd's journal, if needed).
