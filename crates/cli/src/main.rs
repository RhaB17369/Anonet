use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use anonet_bridges::{BridgeManager, TransportBinary};
use anonet_core::AnonCore;
use anonet_socks::{ListenerConfig, SocksServer};
use clap::{Parser, Subcommand};

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
    },
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
        } => run(bind, bridges, pluggable_transports, bridge_timeout_secs).await,
    }
}

async fn run(
    bind: SocketAddr,
    bridges: Vec<String>,
    pluggable_transports: Vec<String>,
    bridge_timeout_secs: u64,
) -> Result<()> {
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
        match manager
            .find_healthy_config(Duration::from_secs(bridge_timeout_secs))
            .await
        {
            Ok((idx, config)) => {
                tracing::info!(candidate = idx, "bridge healthy, bootstrapping real client through it");
                AnonCore::bootstrap_with(config).await?
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "no configured bridge passed its health check; falling back to a direct (bridge-less) Tor connection"
                );
                AnonCore::bootstrap().await?
            }
        }
    };

    let server = SocksServer::new(Arc::new(core));
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
