//! Live health state, published over a `watch` channel: cheap for
//! `anonet-bridges`' health monitor to update, cheap for any number of
//! readers (a log line, a TUI dashboard) to subscribe to without polling.

use std::collections::VecDeque;
use std::time::SystemTime;

use tokio::sync::watch;

/// How many recent health-check outcomes to keep for the active bridge's
/// latency history (used by the TUI's sparkline). Fixed rather than
/// configurable — this is display history, not something worth a CLI flag.
pub const HISTORY_CAPACITY: usize = 120;

/// How many recent transparent-proxy stream events (from Tor's
/// ControlPort) to keep for the TUI's live-traffic panel.
pub const STREAM_EVENTS_CAPACITY: usize = 200;

#[derive(Debug, Clone)]
pub struct HealthSample {
    pub at: SystemTime,
    pub success: bool,
    pub latency_ms: u64,
}

/// Last known status of one configured bridge candidate. Populated when a
/// candidate is actually checked (at startup, or during a failover scan) —
/// candidates further down the list than whichever one is currently active
/// are not checked on every tick (that would mean a full throwaway Tor
/// bootstrap per candidate per tick), so `last_checked_at` can be stale or
/// absent for those.
#[derive(Debug, Clone)]
pub struct CandidateStatus {
    pub index: usize,
    pub line: String,
    pub last_success: Option<bool>,
    pub last_latency_ms: Option<u64>,
    pub last_checked_at: Option<SystemTime>,
}

/// One observed Tor stream (connection) from the ControlPort's `STREAM`
/// events — this is what makes transparently-proxied traffic visible in
/// real time, the same way anonsurf/nyx show it, without anonet having to
/// intercept the connections itself.
#[derive(Debug, Clone)]
pub struct StreamEvent {
    pub at: SystemTime,
    pub status: String,
    pub target: String,
}

#[derive(Debug, Clone, Default)]
pub struct HealthStatus {
    pub active_bridge_index: Option<usize>,
    pub active_bridge_line: Option<String>,
    pub last_check_at: Option<SystemTime>,
    pub last_switch_at: Option<SystemTime>,
    pub consecutive_failures: u32,
    pub total_switches: u64,
    pub history: VecDeque<HealthSample>,
    pub candidates: Vec<CandidateStatus>,
    /// SOCKS5 connections accepted since startup and currently in flight —
    /// a metric that's visible from the moment traffic flows, independent
    /// of whether any bridge is configured.
    pub socks_connections_total: u64,
    pub socks_connections_active: u64,
    /// `Some` once the transparent-proxy `tor` process has started.
    pub transparent_enabled: bool,
    pub recent_streams: VecDeque<StreamEvent>,
}

impl HealthStatus {
    /// Seeds the candidates table with every configured bridge, all
    /// "not yet checked", so the TUI can show the full failover pool from
    /// the start rather than only entries that happen to have been tried.
    pub fn seed_candidates(&mut self, all: &[(usize, String)]) {
        self.candidates = all
            .iter()
            .map(|(index, line)| CandidateStatus {
                index: *index,
                line: line.clone(),
                last_success: None,
                last_latency_ms: None,
                last_checked_at: None,
            })
            .collect();
    }

    pub fn push_sample(&mut self, sample: HealthSample) {
        self.history.push_back(sample);
        while self.history.len() > HISTORY_CAPACITY {
            self.history.pop_front();
        }
    }

    pub fn push_stream_event(&mut self, event: StreamEvent) {
        self.recent_streams.push_back(event);
        while self.recent_streams.len() > STREAM_EVENTS_CAPACITY {
            self.recent_streams.pop_front();
        }
    }

    pub fn record_candidate_result(
        &mut self,
        index: usize,
        line: &str,
        success: bool,
        latency_ms: u64,
    ) {
        let now = Some(SystemTime::now());
        if let Some(c) = self.candidates.iter_mut().find(|c| c.index == index) {
            c.last_success = Some(success);
            c.last_latency_ms = Some(latency_ms);
            c.last_checked_at = now;
        } else {
            self.candidates.push(CandidateStatus {
                index,
                line: line.to_string(),
                last_success: Some(success),
                last_latency_ms: Some(latency_ms),
                last_checked_at: now,
            });
            self.candidates.sort_by_key(|c| c.index);
        }
    }
}

#[derive(Clone)]
pub struct Reporter {
    tx: watch::Sender<HealthStatus>,
}

impl Reporter {
    pub fn update(&self, f: impl FnOnce(&mut HealthStatus)) {
        self.tx.send_modify(f);
    }

    pub fn connection_opened(&self) {
        self.update(|s| {
            s.socks_connections_total += 1;
            s.socks_connections_active += 1;
        });
    }

    pub fn connection_closed(&self) {
        self.update(|s| {
            s.socks_connections_active = s.socks_connections_active.saturating_sub(1);
        });
    }
}

/// Creates a new health-status channel: a `Reporter` for the health monitor
/// to write through, and a `Receiver` any number of consumers can clone and
/// watch independently.
pub fn channel() -> (Reporter, watch::Receiver<HealthStatus>) {
    let (tx, rx) = watch::channel(HealthStatus::default());
    (Reporter { tx }, rx)
}
