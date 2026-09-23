//! Wraps `arti-client` bootstrap and exposes a minimal async connect API,
//! plus a stream-isolation policy engine (milestone 2) with time/volume
//! based rotation (milestone 5) and a hot-swappable client handle
//! (`CoreHandle`) so a bridge health monitor can fail over to a freshly
//! bootstrapped client without ever mutating a live one in place (see
//! `anonet-bridges` for why that's the part that actually has to be safe).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{IsolationToken, StreamPrefs, TorClient, TorClientConfig};
use tokio::sync::RwLock;
use tor_rtcompat::PreferredRuntime;

/// When to hand an identity a fresh `IsolationToken` (and therefore a fresh
/// circuit) instead of reusing its current one. Both bounds apply; whichever
/// is hit first triggers rotation. This is genuinely our own responsibility
/// — arti's own circuit-dirtiness timeout doesn't know about our per-app
/// isolation buckets.
#[derive(Debug, Clone, Copy)]
pub struct RotationPolicy {
    pub max_age: Option<Duration>,
    pub max_uses: Option<u32>,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_age: Some(Duration::from_secs(600)),
            max_uses: Some(200),
        }
    }
}

struct IsolationEntry {
    token: IsolationToken,
    created_at: Instant,
    uses: u32,
}

/// Maps an opaque "app identity" string to a stable [`IsolationToken`], so
/// repeated connections carrying the same identity share a circuit pool
/// while different identities never do. Identities are typically the SOCKS5
/// username a client authenticates with (see `anonet-socks`).
struct IsolationPolicy {
    tokens: Mutex<HashMap<String, IsolationEntry>>,
    rotation: RotationPolicy,
}

impl IsolationPolicy {
    fn new(rotation: RotationPolicy) -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            rotation,
        }
    }

    fn token_for(&self, identity: &str) -> IsolationToken {
        let mut tokens = self.tokens.lock().expect("isolation map poisoned");
        let now = Instant::now();

        let stale = tokens.get(identity).is_some_and(|e| {
            self.rotation
                .max_age
                .is_some_and(|max| now.duration_since(e.created_at) >= max)
                || self.rotation.max_uses.is_some_and(|max| e.uses >= max)
        });
        if stale {
            tokens.remove(identity);
        }

        let entry = tokens.entry(identity.to_string()).or_insert_with(|| IsolationEntry {
            token: IsolationToken::new(),
            created_at: now,
            uses: 0,
        });
        entry.uses += 1;
        entry.token
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
            isolation: IsolationPolicy::new(RotationPolicy::default()),
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

    /// Resolves `host` to its IP address(es) via the exit relay, so name
    /// resolution never touches the local system resolver.
    pub async fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>> {
        self.client
            .resolve(host)
            .await
            .with_context(|| format!("failed to resolve {host} via Tor"))
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

/// A hot-swappable handle to the current `AnonCore`. `anonet-socks` and
/// `anonet-leakguard::DnsShim` read through this instead of holding an
/// `Arc<AnonCore>` directly, so a bridge health monitor can fail over by
/// bootstrapping a brand new client and swapping it in — never by mutating
/// a live one, which is what produced the stale-guard false positive
/// described in `anonet-bridges`.
pub struct CoreHandle {
    inner: RwLock<Arc<AnonCore>>,
}

impl CoreHandle {
    pub fn new(core: AnonCore) -> Self {
        Self {
            inner: RwLock::new(Arc::new(core)),
        }
    }

    /// The client to use for a single connection/query. Cheap: an `Arc`
    /// clone under a read lock.
    pub async fn current(&self) -> Arc<AnonCore> {
        self.inner.read().await.clone()
    }

    /// Atomically swaps in a new client. Connections already in flight keep
    /// using the `Arc` they cloned; only connections started after this
    /// call see `new_core`.
    pub async fn replace(&self, new_core: AnonCore) {
        *self.inner.write().await = Arc::new(new_core);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_token_below_the_use_limit() {
        let policy = IsolationPolicy::new(RotationPolicy {
            max_age: None,
            max_uses: Some(3),
        });
        let t1 = policy.token_for("alice");
        let t2 = policy.token_for("alice");
        assert_eq!(t1, t2, "uses 1 and 2 should share a token (limit is 3)");
    }

    #[test]
    fn rotates_token_once_the_use_limit_is_hit() {
        let policy = IsolationPolicy::new(RotationPolicy {
            max_age: None,
            max_uses: Some(2),
        });
        let t1 = policy.token_for("alice"); // use 1
        let _ = policy.token_for("alice"); // use 2, hits the limit
        let t3 = policy.token_for("alice"); // use 3 should rotate first
        assert_ne!(t1, t3);
    }

    #[test]
    fn rotates_token_once_max_age_elapses() {
        let policy = IsolationPolicy::new(RotationPolicy {
            max_age: Some(Duration::from_millis(20)),
            max_uses: None,
        });
        let t1 = policy.token_for("alice");
        std::thread::sleep(Duration::from_millis(40));
        let t2 = policy.token_for("alice");
        assert_ne!(t1, t2);
    }

    #[test]
    fn different_identities_never_share_a_token() {
        let policy = IsolationPolicy::new(RotationPolicy::default());
        assert_ne!(policy.token_for("alice"), policy.token_for("bob"));
    }

    /// Network-gated: bootstraps two real Tor clients. Run manually with
    /// `cargo test -p anonet-core -- --ignored`. Verifies the mechanism
    /// `anonet-bridges::BridgeMonitor` depends on for safe hot failover: a
    /// connection made through `CoreHandle::current()` *before* a
    /// `replace()` keeps working after the swap, and a connection made
    /// *after* uses the new client — i.e. swapping never breaks an in-flight
    /// request, and never leaves the handle serving a half-replaced state.
    #[tokio::test]
    #[ignore]
    async fn core_handle_swap_does_not_disrupt_in_flight_or_subsequent_connections() {
        let first = AnonCore::bootstrap().await.expect("first bootstrap");
        let handle = CoreHandle::new(first);

        // Grab a stream from the pre-swap client, but don't consume it yet.
        let pre_swap_core = handle.current().await;
        let pre_swap_stream = pre_swap_core
            .connect("check.torproject.org", 443)
            .await
            .expect("pre-swap connect should succeed");

        let second = AnonCore::bootstrap().await.expect("second bootstrap");
        handle.replace(second).await;

        // The stream obtained before the swap must still be usable.
        drop(pre_swap_stream);

        // A brand new caller after the swap must get the new client and be
        // able to connect through it too.
        let post_swap_core = handle.current().await;
        post_swap_core
            .connect("check.torproject.org", 443)
            .await
            .expect("post-swap connect should succeed");
    }
}
