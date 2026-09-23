//! Background bridge health monitoring with hot failover.
//!
//! `BridgeManager::find_healthy_config` (used at startup) only checks once.
//! `BridgeMonitor` re-checks the currently active bridge periodically while
//! `anonet run` is live, and on repeated failure, bootstraps a fresh
//! `AnonCore` through a different candidate and atomically swaps it into
//! the shared `CoreHandle` — never by reconfiguring the live client (see
//! the module-level doc comment in `lib.rs` for why that's unsafe).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use anonet_core::{AnonCore, CoreHandle};
use anonet_telemetry::Reporter;
use tracing::{info, warn};

use crate::BridgeManager;

pub struct BridgeMonitor {
    manager: BridgeManager,
    core_handle: std::sync::Arc<CoreHandle>,
    telemetry: Reporter,
    check_interval: Duration,
    check_timeout: Duration,
    failure_threshold: u32,
    active_idx: AtomicUsize,
}

impl BridgeMonitor {
    pub fn new(
        manager: BridgeManager,
        core_handle: std::sync::Arc<CoreHandle>,
        telemetry: Reporter,
        initial_active_idx: usize,
        check_interval: Duration,
        check_timeout: Duration,
        failure_threshold: u32,
    ) -> Self {
        telemetry.update(|s| {
            s.active_bridge_index = Some(initial_active_idx);
            s.active_bridge_line = manager.candidate_line(initial_active_idx);
        });
        Self {
            manager,
            core_handle,
            telemetry,
            check_interval,
            check_timeout,
            failure_threshold,
            active_idx: AtomicUsize::new(initial_active_idx),
        }
    }

    /// Runs forever, checking the active bridge every `check_interval` and
    /// failing over after `failure_threshold` consecutive failures. Meant
    /// to be spawned as a background task; it never returns under normal
    /// operation.
    pub async fn run(&self) {
        let mut consecutive_failures = 0u32;

        loop {
            tokio::time::sleep(self.check_interval).await;

            let idx = self.active_idx.load(Ordering::SeqCst);
            let result = self.manager.health_check(idx, self.check_timeout).await;
            self.telemetry.update(|s| s.last_check_at = Some(SystemTime::now()));

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
            match self.manager.find_healthy_config(self.check_timeout).await {
                Ok((new_idx, _new_config)) if new_idx == idx => {
                    // The only healthy candidate is the one we already
                    // thought was down — a transient blip, not a real
                    // failover. Reset the counter and keep going.
                    info!("re-check found the current bridge healthy again");
                    consecutive_failures = 0;
                    self.telemetry.update(|s| s.consecutive_failures = 0);
                }
                Ok((new_idx, new_config)) => match AnonCore::bootstrap_with(new_config).await {
                    Ok(new_core) => {
                        self.core_handle.replace(new_core).await;
                        self.active_idx.store(new_idx, Ordering::SeqCst);
                        consecutive_failures = 0;
                        let line = self.manager.candidate_line(new_idx);
                        self.telemetry.update(|s| {
                            s.active_bridge_index = Some(new_idx);
                            s.active_bridge_line = line.clone();
                            s.last_switch_at = Some(SystemTime::now());
                            s.total_switches += 1;
                            s.consecutive_failures = 0;
                        });
                        info!(new_idx, bridge = ?line, "failed over to a new bridge");
                    }
                    Err(err) => {
                        warn!(error = %err, "found a healthy candidate but failed to bootstrap a client for it; keeping current one active");
                    }
                },
                Err(err) => {
                    warn!(error = %err, "no healthy bridge candidate found; keeping current (unhealthy) one active");
                }
            }
        }
    }
}
