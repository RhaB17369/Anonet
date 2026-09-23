//! Live health state, published over a `watch` channel: cheap for
//! `anonet-bridges`' health monitor to update, cheap for any number of
//! readers (a log line today, a TUI dashboard in a later milestone) to
//! subscribe to without polling.

use std::time::SystemTime;

use tokio::sync::watch;

#[derive(Debug, Clone, Default)]
pub struct HealthStatus {
    pub active_bridge_index: Option<usize>,
    pub active_bridge_line: Option<String>,
    pub last_check_at: Option<SystemTime>,
    pub last_switch_at: Option<SystemTime>,
    pub consecutive_failures: u32,
    pub total_switches: u64,
}

#[derive(Clone)]
pub struct Reporter {
    tx: watch::Sender<HealthStatus>,
}

impl Reporter {
    pub fn update(&self, f: impl FnOnce(&mut HealthStatus)) {
        self.tx.send_modify(f);
    }
}

/// Creates a new health-status channel: a `Reporter` for the health monitor
/// to write through, and a `Receiver` any number of consumers can clone and
/// watch independently.
pub fn channel() -> (Reporter, watch::Receiver<HealthStatus>) {
    let (tx, rx) = watch::channel(HealthStatus::default());
    (Reporter { tx }, rx)
}
