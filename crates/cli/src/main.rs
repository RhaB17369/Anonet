use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
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
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run { bind } => run(bind).await,
    }
}

async fn run(bind: SocketAddr) -> Result<()> {
    tracing::info!("bootstrapping Tor client (this can take a few seconds)");
    let core = Arc::new(AnonCore::bootstrap().await?);
    tracing::info!("Tor client bootstrapped");

    let server = SocksServer::new(core);
    server.run(ListenerConfig { bind }).await
}
