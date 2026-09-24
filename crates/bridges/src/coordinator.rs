//! Background bridge health monitoring with hot failover, plus live bridge
//! addition (`try_add_bridge`) — the mechanism a dynamic front end (the
//! TUI) uses to let the user type in a new bridge line and have it tried
//! and, if healthy, activated without restarting the process.
//!
//! `BridgeManager::find_healthy_config` (used at startup) only checks once.
//! `BridgeCoordinator` re-checks the currently active bridge periodically
//! while `anonet run` is live, and on repeated failure (or a manual
//! `try_add_bridge` success), bootstraps a fresh `AnonCore` through a
//! different candidate and atomically swaps it into the shared
//! `CoreHandle` — never by reconfiguring the live client (see the
//! module-level doc comment in `lib.rs` for why that's unsafe).

use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow};
use anonet_core::{AnonCore, CoreHandle};
use anonet_telemetry::{HealthSample, Reporter};
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::BridgeManager;

pub struct BridgeCoordinator {
    manager: Arc<BridgeManager>,
    core_handle: Arc<CoreHandle>,
    telemetry: Reporter,
    check_interval: Duration,
    check_timeout: Duration,
    failure_threshold: u32,
    /// `None` when no bridge is active yet (direct mode, or no candidate
    /// has ever succeeded). Shared so `try_add_bridge` and the periodic
    /// loop agree on what's currently active.
    active_idx: Arc<StdMutex<Option<usize>>>,
    /// Lets a caller (e.g. the TUI's "check now" key) wake the loop early
    /// instead of waiting out the rest of `check_interval`.
    check_now: Arc<Notify>,
}

impl BridgeCoordinator {
    pub fn new(
        manager: Arc<BridgeManager>,
        core_handle: Arc<CoreHandle>,
        telemetry: Reporter,
        initial_active_idx: Option<usize>,
        check_interval: Duration,
        check_timeout: Duration,
        failure_threshold: u32,
        check_now: Arc<Notify>,
    ) -> Self {
        if let Some(idx) = initial_active_idx {
            telemetry.update(|s| {
                s.active_bridge_index = Some(idx);
                s.active_bridge_line = manager.candidate_line(idx);
            });
        }
        Self {
            manager,
            core_handle,
            telemetry,
            check_interval,
            check_timeout,
            failure_threshold,
            active_idx: Arc::new(StdMutex::new(initial_active_idx)),
            check_now,
        }
    }

    fn active(&self) -> Option<usize> {
        *self.active_idx.lock().expect("poisoned")
    }

    /// Runs forever, checking the active bridge every `check_interval` (or
    /// immediately when `check_now` is notified) and failing over after
    /// `failure_threshold` consecutive failures. If no bridge is active
    /// (direct mode, or nothing configured yet), it just idles — waking on
    /// `check_now` is what lets `try_add_bridge` take effect promptly once
    /// it activates the first candidate. Meant to be spawned as a
    /// background task; it never returns under normal operation.
    pub async fn run(&self) {
        let mut consecutive_failures = 0u32;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.check_interval) => {}
                _ = self.check_now.notified() => {}
            }

            let Some(idx) = self.active() else {
                continue;
            };

            let result = self.manager.health_check(idx, self.check_timeout).await;
            let line = result.candidate_line.clone();
            let latency_ms = result.latency.as_millis() as u64;
            self.telemetry.update(|s| {
                s.last_check_at = Some(SystemTime::now());
                s.push_sample(HealthSample {
                    at: SystemTime::now(),
                    success: result.success,
                    latency_ms,
                });
                s.record_candidate_result(idx, &line, result.success, latency_ms);
            });

            if result.success {
                if consecutive_failures > 0 {
                    info!(bridge = %result.candidate_line, "active bridge recovered");
                }
                consecutive_failures = 0;
                self.telemetry.update(|s| s.consecutive_failures = 0);
                continue;
            }

            consecutive_failures += 1;
            self.telemetry.update(|s| s.consecutive_failures = consecutive_failures);
            warn!(
                bridge = %result.candidate_line,
                consecutive_failures,
                threshold = self.failure_threshold,
                "active bridge health check failed"
            );

            if consecutive_failures < self.failure_threshold {
                continue;
            }

            warn!("failure threshold reached, searching for a replacement bridge");
            if self.rescan_and_activate(Some(idx)).await {
                consecutive_failures = 0;
            }
        }
    }

    /// Scans all configured candidates (skipping the report-only case where
    /// the winner is the same as `skip_if_same`, which just means "still
    /// down, nothing changed") and activates the first healthy one found.
    /// Returns `true` if the failure counter should reset (either a real
    /// failover happened, or the "failed" bridge turned out to be healthy
    /// again on re-check).
    async fn rescan_and_activate(&self, skip_if_same: Option<usize>) -> bool {
        let telemetry = &self.telemetry;
        let scan = self
            .manager
            .find_healthy_config_reporting(self.check_timeout, |cand_idx, cand_result| {
                telemetry.update(|s| {
                    s.record_candidate_result(
                        cand_idx,
                        &cand_result.candidate_line,
                        cand_result.success,
                        cand_result.latency.as_millis() as u64,
                    );
                });
            })
            .await;

        match scan {
            Ok((new_idx, _)) if Some(new_idx) == skip_if_same => {
                info!("re-check found the current bridge healthy again");
                self.telemetry.update(|s| s.consecutive_failures = 0);
                true
            }
            Ok((new_idx, new_config)) => match AnonCore::bootstrap_with(new_config).await {
                Ok(new_core) => {
                    self.core_handle.replace(new_core).await;
                    *self.active_idx.lock().expect("poisoned") = Some(new_idx);
                    let line = self.manager.candidate_line(new_idx);
                    self.telemetry.update(|s| {
                        s.active_bridge_index = Some(new_idx);
                        s.active_bridge_line = line.clone();
                        s.last_switch_at = Some(SystemTime::now());
                        s.total_switches += 1;
                        s.consecutive_failures = 0;
                    });
                    info!(new_idx, bridge = ?line, "activated bridge");
                    true
                }
                Err(err) => {
                    warn!(error = %err, "found a healthy candidate but failed to bootstrap a client for it");
                    false
                }
            },
            Err(err) => {
                warn!(error = %err, "no healthy bridge candidate found");
                false
            }
        }
    }

    /// Adds `line` as a new candidate, health-checks it, and — if it
    /// passes — bootstraps a fresh client through it and hot-swaps it in
    /// as the active bridge, exactly like an automatic failover would.
    /// Meant to be called from an interactive front end (the TUI); safe to
    /// run concurrently with the background `run()` loop since both only
    /// ever touch `active_idx` and `core_handle` through their shared
    /// locks/atomics.
    pub async fn try_add_bridge(&self, line: &str) -> Result<usize> {
        self.telemetry.update(|s| s.clear_error());
        let idx = match self.manager.add_bridge_line(line) {
            Ok(idx) => idx,
            Err(err) => {
                let msg = err.to_string();
                self.telemetry.update(|s| s.record_error(msg.clone()));
                return Err(err);
            }
        };
        let result = self.manager.health_check(idx, self.check_timeout).await;
        let latency_ms = result.latency.as_millis() as u64;
        self.telemetry.update(|s| {
            s.record_candidate_result(idx, &result.candidate_line, result.success, latency_ms);
        });

        if !result.success {
            let msg = format!(
                "new bridge failed its health check: {}",
                result.error.unwrap_or_else(|| "unknown error".to_string())
            );
            self.telemetry.update(|s| s.record_error(msg.clone()));
            return Err(anyhow!(msg));
        }

        let config = self.manager.production_config(idx)?;
        let new_core = AnonCore::bootstrap_with(config).await?;
        self.core_handle.replace(new_core).await;
        *self.active_idx.lock().expect("poisoned") = Some(idx);
        let active_line = self.manager.candidate_line(idx);
        self.telemetry.update(|s| {
            s.active_bridge_index = Some(idx);
            s.active_bridge_line = active_line.clone();
            s.last_switch_at = Some(SystemTime::now());
            s.total_switches += 1;
            s.consecutive_failures = 0;
        });
        info!(idx, bridge = ?active_line, "manually added bridge activated");
        Ok(idx)
    }
}
