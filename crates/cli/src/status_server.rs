//! Unix-socket status endpoint so `anonet status` — a separate, short-lived
//! process — can see a running `anonet run` instance's live state without
//! parsing its log file or opening the dashboard. One snapshot per
//! connection: the client connects, reads until EOF, and the server closes
//! the stream. No request body; connecting *is* the request.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::sync::watch;

use anonet_leakguard::DnsShimController;
use anonet_telemetry::HealthStatus;

pub fn socket_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("anonet")
        .join("anonet.sock")
}

/// Binds the status socket and serves snapshots until the process exits.
/// Removes a stale socket file first — the same "just take over" policy
/// `instance_lock` applies to the PID file, since a leftover socket path
/// from a crashed previous instance otherwise makes `UnixListener::bind`
/// fail even though nothing is actually listening on it anymore.
pub async fn serve(
    socks_addr: SocketAddr,
    health_rx: watch::Receiver<HealthStatus>,
    dns_controller: Arc<DnsShimController>,
) -> Result<()> {
    let path = socket_path();
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("failed to bind status socket at {}", path.display()))?;

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(error = %err, "status socket accept failed");
                continue;
            }
        };
        let health = health_rx.borrow().clone();
        let dns_addr = dns_controller.bound_addr();
        let text = format_status(socks_addr, &health, dns_addr);
        if let Err(err) = stream.write_all(text.as_bytes()).await {
            tracing::debug!(error = %err, "status client disconnected before the snapshot was fully sent");
        }
    }
}

fn format_status(socks_addr: SocketAddr, health: &HealthStatus, dns_addr: Option<SocketAddr>) -> String {
    let dns_shim = dns_addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "stopped".to_string());
    let active_bridge = health
        .active_bridge_line
        .as_deref()
        .unwrap_or("none (direct connection)");
    let last_error = health
        .last_error
        .as_ref()
        .map(|(_, msg)| msg.as_str())
        .unwrap_or("none");
    let full_anon = if health.transparent_enabled { "running" } else { "stopped" };

    format!(
        "socks_listening: {socks_addr}\n\
         socks_connections_active: {}\n\
         socks_connections_total: {}\n\
         dns_shim: {dns_shim}\n\
         active_bridge: {active_bridge}\n\
         bridge_candidates: {}\n\
         consecutive_failures: {}\n\
         total_bridge_switches: {}\n\
         full_anonymization: {full_anon}\n\
         last_error: {last_error}\n",
        health.socks_connections_active,
        health.socks_connections_total,
        health.candidates.len(),
        health.consecutive_failures,
        health.total_switches,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_direct_connection_and_stopped_services_by_default() {
        let health = HealthStatus::default();
        let text = format_status("127.0.0.1:9450".parse().unwrap(), &health, None);
        assert!(text.contains("socks_listening: 127.0.0.1:9450"));
        assert!(text.contains("active_bridge: none (direct connection)"));
        assert!(text.contains("dns_shim: stopped"));
        assert!(text.contains("full_anonymization: stopped"));
        assert!(text.contains("last_error: none"));
    }

    #[test]
    fn reports_active_bridge_and_dns_shim_when_present() {
        let mut health = HealthStatus::default();
        health.active_bridge_line = Some("Bridge obfs4 1.2.3.4:443 ...".to_string());
        health.transparent_enabled = true;
        health.record_error("boom");
        let dns_addr: SocketAddr = "127.0.0.1:9535".parse().unwrap();
        let text = format_status("127.0.0.1:9450".parse().unwrap(), &health, Some(dns_addr));
        assert!(text.contains("active_bridge: Bridge obfs4 1.2.3.4:443"));
        assert!(text.contains("dns_shim: 127.0.0.1:9535"));
        assert!(text.contains("full_anonymization: running"));
        assert!(text.contains("last_error: boom"));
    }
}
