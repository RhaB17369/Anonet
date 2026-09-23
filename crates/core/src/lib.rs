//! Wraps `arti-client` bootstrap and exposes a minimal async connect API,
//! plus a stream-isolation policy engine (milestone 2). Circuit
//! health/rotation lands in a later milestone.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{IsolationToken, StreamPrefs, TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

/// Maps an opaque "app identity" string to a stable [`IsolationToken`], so
/// repeated connections carrying the same identity share a circuit pool
/// while different identities never do. Identities are typically the SOCKS5
/// username a client authenticates with (see `anonet-socks`).
#[derive(Default)]
struct IsolationPolicy {
    tokens: Mutex<HashMap<String, IsolationToken>>,
}

impl IsolationPolicy {
    fn token_for(&self, identity: &str) -> IsolationToken {
        let mut tokens = self.tokens.lock().expect("isolation map poisoned");
        *tokens
            .entry(identity.to_string())
            .or_insert_with(IsolationToken::new)
    }
}

pub struct AnonCore {
    client: Arc<TorClient<PreferredRuntime>>,
    isolation: IsolationPolicy,
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
        Ok(Self {
            client,
            isolation: IsolationPolicy::default(),
        })
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

    /// Opens an anonymized stream isolated by `identity`: connections that
    /// share an identity may share a circuit; connections with different
    /// identities never do.
    pub async fn connect_isolated(
        &self,
        host: &str,
        port: u16,
        identity: &str,
    ) -> Result<arti_client::DataStream> {
        let token = self.isolation.token_for(identity);
        let mut prefs = StreamPrefs::new();
        prefs.set_isolation(token);
        self.client
            .connect_with_prefs((host, port), &prefs)
            .await
            .with_context(|| format!("failed to connect to {host}:{port} via Tor (isolation={identity})"))
    }

    pub fn inner(&self) -> &TorClient<PreferredRuntime> {
        &self.client
    }

    /// Applies a new configuration (e.g. an updated bridge/PT set) to the
    /// running client. Best-effort: fields that cannot be changed on a live
    /// client are warned about rather than treated as a hard failure, since
    /// bridge rotation should degrade gracefully rather than crash the proxy.
    pub fn reconfigure(&self, config: &TorClientConfig) -> Result<()> {
        self.client
            .reconfigure(config, tor_config::Reconfigure::WarnOnFailures)
            .context("failed to apply new Tor client configuration")
    }
}
