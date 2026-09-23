mod control;
mod full_anon;
mod supervisor;

use std::sync::Arc;

use anyhow::Result;
use anonet_telemetry::Reporter;

pub use full_anon::FullAnonController;
pub use supervisor::{TorPorts, TorSupervisor};

/// Starts the supervised `tor` process and, once it's bootstrapped, spawns
/// the background task that feeds its ControlPort STREAM events into
/// `telemetry`. Returns once `tor` has finished bootstrapping; the event
/// feed keeps running in the background after that.
pub async fn start(supervisor: &mut TorSupervisor, telemetry: Reporter) -> Result<()> {
    supervisor.start().await?;
    let control_port = supervisor.ports().control_port;
    let cookie_path = supervisor.cookie_path();
    let telemetry = Arc::new(telemetry);
    tokio::spawn(async move {
        if let Err(err) = control::watch_streams(control_port, &cookie_path, telemetry).await {
            tracing::warn!(error = %err, "tor ControlPort stream watcher stopped");
        }
    });
    Ok(())
}
