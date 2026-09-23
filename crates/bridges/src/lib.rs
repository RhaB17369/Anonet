//! Bridge/pluggable-transport ingestion, config generation, health checks
//! and failover ordering.
//!
//! This crate does not reimplement obfs4/snowflake or manage their process
//! lifecycle — `tor-ptmgr` (inside `arti-client`) already launches and
//! monitors the configured PT binaries. Our job is: parse bridge lines,
//! build the resulting `TorClientConfig`, decide (by actually bootstrapping
//! a throwaway client through each one) which configured bridge works, and
//! hand the winning config back to the caller to bootstrap the real,
//! long-lived `AnonCore` with.
//!
//! # Why health checks use a throwaway client, not the shared one
//!
//! An earlier version of this health check called `AnonCore::reconfigure`
//! on the already-bootstrapped, shared client. That produced a false
//! positive: the shared client still had a real, working guard cached from
//! its initial (bridge-less) bootstrap, and a connection made moments after
//! `reconfigure()` could race onto that stale guard instead of the new
//! (and, in testing, deliberately non-routable) bridge — reporting success
//! for a bridge that was never actually used. Bootstrapping a fresh
//! `AnonCore` with its own temporary state/cache directories for each
//! candidate has no prior guard state to race with: if it reports success,
//! the connection could only have gone through the bridge that config
//! names. The real client is only ever bootstrapped (not reconfigured)
//! with the winning config, so it never carries over a stale direct-Tor
//! guard either.

mod coordinator;

pub use coordinator::BridgeCoordinator;

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfig, TorClientConfigBuilder};
use tracing::{info, warn};

use anonet_core::AnonCore;

/// A pluggable-transport binary to register with Arti's transport manager
/// (e.g. `obfs4` -> `/usr/bin/obfs4proxy`).
#[derive(Clone, Debug)]
pub struct TransportBinary {
    pub protocol: String,
    pub path: PathBuf,
}

impl TransportBinary {
    pub fn new(protocol: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            protocol: protocol.into(),
            path: path.into(),
        }
    }

    fn to_builder(&self) -> Result<TransportConfigBuilder> {
        let mut builder = TransportConfigBuilder::default();
        builder
            .protocols(vec![self
                .protocol
                .parse()
                .with_context(|| format!("invalid pluggable transport protocol name '{}'", self.protocol))?])
            .path(CfgPath::new(self.path.to_string_lossy().into_owned()))
            .run_on_startup(true);
        Ok(builder)
    }
}

/// One candidate bridge, kept alongside its original bridge line for
/// logging/diagnostics.
#[derive(Clone)]
struct Candidate {
    line: String,
    builder: BridgeConfigBuilder,
}

/// Parses a torrc-style `Bridge ...` line (the same syntax Tor Browser and
/// `torrc` use) to validate it eagerly, without keeping it anywhere.
pub fn parse_bridge_line(line: &str) -> Result<()> {
    let _: BridgeConfigBuilder = line
        .parse()
        .map_err(|e| anyhow!("invalid bridge line '{line}': {e}"))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct HealthResult {
    pub candidate_line: String,
    pub success: bool,
    pub latency: Duration,
    pub error: Option<String>,
}

pub struct BridgeManager {
    transports: Vec<TransportBinary>,
    candidates: Mutex<Vec<Candidate>>,
}

impl BridgeManager {
    pub fn new(transports: Vec<TransportBinary>) -> Self {
        Self {
            transports,
            candidates: Mutex::new(Vec::new()),
        }
    }

    /// Adds a bridge line to the end of the failover order and returns its
    /// index. Bridges added first are preferred; `find_healthy_config`
    /// tries them in order. Safe to call at any time, including while
    /// `BridgeCoordinator::run` is already active — candidates are behind
    /// a mutex specifically so this can be driven live (e.g. from the TUI).
    pub fn add_bridge_line(&self, line: &str) -> Result<usize> {
        let builder: BridgeConfigBuilder = line
            .parse()
            .map_err(|e| anyhow!("invalid bridge line '{line}': {e}"))?;
        let mut candidates = self.candidates.lock().expect("poisoned");
        candidates.push(Candidate {
            line: line.to_string(),
            builder,
        });
        Ok(candidates.len() - 1)
    }

    pub fn candidate_count(&self) -> usize {
        self.candidates.lock().expect("poisoned").len()
    }

    /// All configured candidates as `(index, line)`, in failover order.
    pub fn all_candidates(&self) -> Vec<(usize, String)> {
        self.candidates
            .lock()
            .expect("poisoned")
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.line.clone()))
            .collect()
    }

    pub fn candidate_line(&self, idx: usize) -> Option<String> {
        self.candidates.lock().expect("poisoned").get(idx).map(|c| c.line.clone())
    }

    fn candidate(&self, idx: usize) -> Result<Candidate> {
        self.candidates
            .lock()
            .expect("poisoned")
            .get(idx)
            .cloned()
            .ok_or_else(|| anyhow!("no bridge candidate at index {idx}"))
    }

    /// Builds a `TorClientConfig` enabling exactly one candidate bridge
    /// (plus all registered transport binaries), on top of `base` (which
    /// controls where state/cache data lives — a temp dir for health
    /// checks, the default location for the real client).
    fn build_config(&self, idx: usize, mut base: TorClientConfigBuilder) -> Result<TorClientConfig> {
        let candidate = self.candidate(idx)?;
        base.bridges().bridges().push(candidate.builder);
        for t in &self.transports {
            base.bridges().transports().push(t.to_builder()?);
        }
        base.build()
            .context("failed to build TorClientConfig for bridge candidate")
    }

    /// The config a real, long-lived client should use once `idx` has been
    /// confirmed healthy: same bridge/transport set, default storage
    /// locations.
    pub fn production_config(&self, idx: usize) -> Result<TorClientConfig> {
        self.build_config(idx, TorClientConfig::builder())
    }

    /// Bootstraps a throwaway `AnonCore` in a fresh temp dir (so it can't
    /// inherit guard state from anywhere else) using only candidate `idx`,
    /// then attempts one real connection through it. The throwaway client
    /// and its temp directories are dropped when this returns.
    pub async fn health_check(&self, idx: usize, timeout: Duration) -> HealthResult {
        let line = self
            .candidate(idx)
            .map(|c| c.line)
            .unwrap_or_default();

        let state_dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(err) => {
                return HealthResult {
                    candidate_line: line,
                    success: false,
                    latency: Duration::ZERO,
                    error: Some(format!("failed to create temp state dir: {err}")),
                };
            }
        };
        let cache_dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(err) => {
                return HealthResult {
                    candidate_line: line,
                    success: false,
                    latency: Duration::ZERO,
                    error: Some(format!("failed to create temp cache dir: {err}")),
                };
            }
        };

        let config = match self.build_config(
            idx,
            TorClientConfigBuilder::from_directories(state_dir.path(), cache_dir.path()),
        ) {
            Ok(c) => c,
            Err(err) => {
                return HealthResult {
                    candidate_line: line,
                    success: false,
                    latency: Duration::ZERO,
                    error: Some(err.to_string()),
                };
            }
        };

        let start = Instant::now();
        let outcome = tokio::time::timeout(timeout, async {
            let core = AnonCore::bootstrap_with(config).await?;
            core.connect_isolated("check.torproject.org", 443, "bridge-health-check")
                .await?;
            Ok::<(), anyhow::Error>(())
        })
        .await;

        // Keep the temp dirs alive until the whole check is done.
        drop(state_dir);
        drop(cache_dir);

        match outcome {
            Ok(Ok(())) => HealthResult {
                candidate_line: line,
                success: true,
                latency: start.elapsed(),
                error: None,
            },
            Ok(Err(err)) => HealthResult {
                candidate_line: line,
                success: false,
                latency: start.elapsed(),
                error: Some(err.to_string()),
            },
            Err(_elapsed) => HealthResult {
                candidate_line: line,
                success: false,
                latency: timeout,
                error: Some(format!("health check timed out after {timeout:?}")),
            },
        }
    }

    /// Tries each configured bridge in order (via an isolated throwaway
    /// client each time) and returns the index and production config of the
    /// first one that actually works.
    pub async fn find_healthy_config(&self, timeout: Duration) -> Result<(usize, TorClientConfig)> {
        self.find_healthy_config_reporting(timeout, |_, _| {}).await
    }

    /// Same as `find_healthy_config`, but calls `on_result(idx, &result)`
    /// for every candidate it actually tries — including the ones that
    /// fail before the winner is found — so a caller (the CLI, wiring up
    /// telemetry) can keep a "last known status" table for every
    /// configured bridge, not just the one that ends up active.
    pub async fn find_healthy_config_reporting(
        &self,
        timeout: Duration,
        mut on_result: impl FnMut(usize, &HealthResult),
    ) -> Result<(usize, TorClientConfig)> {
        let count = self.candidate_count();
        if count == 0 {
            return Err(anyhow!("no bridge candidates configured"));
        }

        for idx in 0..count {
            let result = self.health_check(idx, timeout).await;
            on_result(idx, &result);
            if result.success {
                info!(
                    bridge = %result.candidate_line,
                    latency_ms = result.latency.as_millis(),
                    "bridge health check succeeded"
                );
                let config = self.production_config(idx)?;
                return Ok((idx, config));
            }
            warn!(
                bridge = %result.candidate_line,
                error = ?result.error,
                "bridge health check failed, trying next candidate"
            );
        }

        Err(anyhow!("all {count} configured bridges failed their health check"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_OBFS4_LINE: &str = "Bridge obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";

    #[test]
    fn parses_a_valid_obfs4_bridge_line() {
        parse_bridge_line(FAKE_OBFS4_LINE).expect("known-good bridge line should parse");
    }

    #[test]
    fn rejects_garbage_bridge_line() {
        assert!(parse_bridge_line("not a bridge line").is_err());
    }

    #[test]
    fn transport_binary_builds_valid_config() {
        let t = TransportBinary::new("obfs4", "/usr/bin/obfs4proxy");
        t.to_builder().expect("well-formed transport should build");
    }

    #[test]
    fn transport_binary_rejects_bad_protocol_name() {
        let t = TransportBinary::new("not a protocol name!!", "/usr/bin/obfs4proxy");
        assert!(t.to_builder().is_err());
    }

    #[test]
    fn failover_order_is_preserved() {
        let manager = BridgeManager::new(vec![TransportBinary::new("obfs4", "/usr/bin/obfs4proxy")]);
        manager.add_bridge_line(FAKE_OBFS4_LINE).unwrap();
        manager
            .add_bridge_line("Bridge obfs4 198.51.100.9:443 7DD62766BF2052432051D7B7E08A22F7E34A4543 cert=YnV0IHNvbWV0aW1lcyB0aGV5IGFyZSByYW5kb20u8x9aQG/0cIIcx0ItBcTqiSXotQne+Q iat-mode=0")
            .unwrap();
        assert_eq!(manager.candidate_count(), 2);
        // production_config should succeed for both indices independently.
        manager.production_config(0).unwrap();
        manager.production_config(1).unwrap();
        assert!(manager.production_config(2).is_err());
    }
}
