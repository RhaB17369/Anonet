//! Wraps `arti-client` bootstrap and exposes a minimal async connect API.
//! Isolation policy and circuit lifecycle management land in later milestones.

use anyhow::{Context, Result};
use arti_client::{TorClient, TorClientConfig};
use arti_client::config::TorClientConfigBuilder;
use tor_rtcompat::PreferredRuntime;

pub struct AnonCore {
    client: std::sync::Arc<TorClient<PreferredRuntime>>,
}

impl AnonCore {
    /// Bootstraps a Tor client against the live public Tor network.
    pub async fn bootstrap() -> Result<Self> {
        Self::bootstrap_with(TorClientConfig::default()).await
    }

    pub async fn bootstrap_with(config: TorClientConfig) -> Result<Self> {
        let client = TorClient::create_bootstrapped(config)
            .await
            .context("failed to bootstrap Tor client")?;
        Ok(Self { client })
    }

    pub fn config_builder() -> TorClientConfigBuilder {
        TorClientConfig::builder()
    }

    /// Opens an anonymized TCP-like stream to `host:port` over the default
    /// (unisolated) circuit pool.
    pub async fn connect(&self, host: &str, port: u16) -> Result<arti_client::DataStream> {
        self.client
            .connect((host, port))
            .await
            .with_context(|| format!("failed to connect to {host}:{port} via Tor"))
    }

    pub fn inner(&self) -> &TorClient<PreferredRuntime> {
        &self.client
    }
}
