use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use anonet_bridges::{BridgeManager, BridgeMonitor, TransportBinary};
use anonet_core::{AnonCore, CoreHandle};
use anonet_leakguard::{DnsShim, KillSwitch, current_uid};
use anonet_socks::{ListenerConfig, SocksServer};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "anonet", version, about = "Rust orchestration layer on top of Tor")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap Tor and run the local SOCKS5 front end.
    Run {
        #[arg(long, default_value = "127.0.0.1:9450")]
        bind: SocketAddr,

        /// A torrc-style `Bridge ...` line. Repeatable; tried in order until
        /// one passes its health check.
        #[arg(long = "bridge", value_name = "LINE")]
        bridges: Vec<String>,

        /// A pluggable-transport binary to register, as `protocol=/path/to/binary`
        /// (e.g. `obfs4=/usr/bin/obfs4proxy`). Repeatable.
        #[arg(long = "pt", value_name = "PROTOCOL=PATH")]
        pluggable_transports: Vec<String>,

        /// Seconds to wait for a bridge health check before trying the next one.
        #[arg(long, default_value_t = 30)]
        bridge_timeout_secs: u64,

        /// Also run a DNS-over-UDP shim on this address, resolving every
        /// query via Tor. For apps that resolve names themselves instead of
        /// using SOCKS5 hostname CONNECT.
        #[arg(long = "dns-shim", value_name = "ADDR")]
        dns_shim: Option<SocketAddr>,

        /// Seconds between background health checks of the active bridge
        /// once running. Only meaningful when --bridge is used.
        #[arg(long, default_value_t = 60)]
        bridge_check_interval_secs: u64,

        /// Consecutive failed health checks before searching for a
        /// replacement bridge.
        #[arg(long, default_value_t = 3)]
        bridge_failure_threshold: u32,
    },

    /// Manage the nftables kill switches. Requires root.
    Killswitch {
        #[command(subcommand)]
        action: KillswitchAction,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum KsMode {
    /// Confine one UID to loopback only (protects that one app).
    Scoped,
    /// Drop all non-loopback egress except anonet's own UID (whole-machine).
    Radical,
}

#[derive(Subcommand)]
enum KillswitchAction {
    /// Apply a kill switch.
    Enable {
        #[arg(long, value_enum)]
        mode: KsMode,

        /// UID to confine to loopback. Required for --mode scoped.
        #[arg(long)]
        protect_uid: Option<u32>,

        /// Auto-disable after this many seconds (or on Ctrl+C). Strongly
        /// recommended for --mode radical, since it can otherwise cut off
        /// this machine's normal network access until you remember to run
        /// `killswitch disable` yourself.
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    /// Remove a kill switch (idempotent: fine to call if it's already off).
    Disable {
        #[arg(long, value_enum)]
        mode: KsMode,
    },
    /// Report whether each kill switch is currently active.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            bind,
            bridges,
            pluggable_transports,
            bridge_timeout_secs,
            dns_shim,
            bridge_check_interval_secs,
            bridge_failure_threshold,
        } => {
            run(
                bind,
                bridges,
                pluggable_transports,
                bridge_timeout_secs,
                dns_shim,
                bridge_check_interval_secs,
                bridge_failure_threshold,
            )
            .await
        }
        Command::Killswitch { action } => killswitch(action).await,
    }
}

async fn killswitch(action: KillswitchAction) -> Result<()> {
    match action {
        KillswitchAction::Enable {
            mode,
            protect_uid,
            ttl_secs,
        } => {
            let ks = match mode {
                KsMode::Scoped => {
                    let uid = protect_uid
                        .ok_or_else(|| anyhow!("--mode scoped requires --protect-uid <uid>"))?;
                    KillSwitch::Scoped { protect_uid: uid }
                }
                KsMode::Radical => {
                    let uid = current_uid().await?;
                    tracing::info!(anonet_uid = uid, "radical kill switch will exempt this process's own UID");
                    KillSwitch::Radical { anonet_uid: uid }
                }
            };

            let ttl_secs = ttl_secs.or(match mode {
                KsMode::Radical => Some(300),
                KsMode::Scoped => None,
            });

            ks.enable().await?;
            tracing::info!(mode = mode_label(mode), "kill switch enabled");

            match ttl_secs {
                None => {
                    println!("Kill switch enabled with no TTL. Run `anonet killswitch disable --mode {}` to remove it.", mode_label(mode));
                    Ok(())
                }
                Some(secs) => {
                    println!(
                        "Kill switch enabled for up to {secs}s (Ctrl+C disables it immediately)."
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(secs)) => {
                            tracing::info!("TTL elapsed, disabling kill switch");
                        }
                        _ = tokio::signal::ctrl_c() => {
                            tracing::info!("Ctrl+C received, disabling kill switch");
                        }
                    }
                    ks.disable().await?;
                    println!("Kill switch disabled.");
                    Ok(())
                }
            }
        }
        KillswitchAction::Disable { mode } => {
            let ks = match mode {
                KsMode::Scoped => KillSwitch::Scoped { protect_uid: 0 },
                KsMode::Radical => KillSwitch::Radical { anonet_uid: 0 },
            };
            ks.disable().await?;
            println!("Kill switch ({}) disabled.", mode_label(mode));
            Ok(())
        }
        KillswitchAction::Status => {
            let scoped = KillSwitch::Scoped { protect_uid: 0 }.is_enabled().await?;
            let radical = KillSwitch::Radical { anonet_uid: 0 }.is_enabled().await?;
            println!("scoped:  {}", if scoped { "ENABLED" } else { "disabled" });
            println!("radical: {}", if radical { "ENABLED" } else { "disabled" });
            Ok(())
        }
    }
}

fn mode_label(mode: KsMode) -> &'static str {
    match mode {
        KsMode::Scoped => "scoped",
        KsMode::Radical => "radical",
    }
}

async fn run(
    bind: SocketAddr,
    bridges: Vec<String>,
    pluggable_transports: Vec<String>,
    bridge_timeout_secs: u64,
    dns_shim: Option<SocketAddr>,
    bridge_check_interval_secs: u64,
    bridge_failure_threshold: u32,
) -> Result<()> {
    let (telemetry, mut health_rx) = anonet_telemetry::channel();

    // Log every telemetry change, so live health/failover state is visible
    // today without needing the jalon-6 TUI to read the same channel.
    tokio::spawn(async move {
        while health_rx.changed().await.is_ok() {
            let status = health_rx.borrow().clone();
            tracing::info!(
                active_bridge = ?status.active_bridge_line,
                consecutive_failures = status.consecutive_failures,
                total_switches = status.total_switches,
                "health status updated"
            );
        }
    });

    let mut active_bridge_idx: Option<usize> = None;
    let mut bridge_manager: Option<BridgeManager> = None;

    let core = if bridges.is_empty() {
        tracing::info!("bootstrapping Tor client (this can take a few seconds)");
        let core = AnonCore::bootstrap().await?;
        tracing::info!("Tor client bootstrapped");
        core
    } else {
        let transports = pluggable_transports
            .iter()
            .map(|spec| parse_pt_spec(spec))
            .collect::<Result<Vec<_>>>()?;

        let manager = BridgeManager::new(transports);
        for line in &bridges {
            manager.add_bridge_line(line)?;
        }

        tracing::info!(count = bridges.len(), "checking configured bridges");
        let core = match manager
            .find_healthy_config(Duration::from_secs(bridge_timeout_secs))
            .await
        {
            Ok((idx, config)) => {
                tracing::info!(candidate = idx, "bridge healthy, bootstrapping real client through it");
                active_bridge_idx = Some(idx);
                AnonCore::bootstrap_with(config).await?
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "no configured bridge passed its health check; falling back to a direct (bridge-less) Tor connection"
                );
                AnonCore::bootstrap().await?
            }
        };
        bridge_manager = Some(manager);
        core
    };

    let handle = Arc::new(CoreHandle::new(core));

    if let (Some(manager), Some(idx)) = (bridge_manager, active_bridge_idx) {
        let monitor = BridgeMonitor::new(
            manager,
            Arc::clone(&handle),
            telemetry,
            idx,
            Duration::from_secs(bridge_check_interval_secs),
            Duration::from_secs(bridge_timeout_secs),
            bridge_failure_threshold,
        );
        tokio::spawn(async move {
            monitor.run().await;
        });
    }

    if let Some(dns_bind) = dns_shim {
        let shim = DnsShim::new(Arc::clone(&handle));
        tokio::spawn(async move {
            if let Err(err) = shim.run(dns_bind).await {
                tracing::error!(error = %err, "DNS shim stopped");
            }
        });
    }

    let server = SocksServer::new(handle);
    server.run(ListenerConfig { bind }).await
}

fn parse_pt_spec(spec: &str) -> Result<TransportBinary> {
    let (protocol, path) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("--pt must be formatted as protocol=/path/to/binary, got '{spec}'"))?;
    if protocol.is_empty() || path.is_empty() {
        return Err(anyhow!("--pt protocol and path must both be non-empty (got '{spec}')"));
    }
    Ok(TransportBinary::new(protocol, path))
}
