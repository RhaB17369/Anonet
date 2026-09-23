//! Glues together the three pieces "full system anonymization" actually
//! means: a supervised `tor` process with TransPort/DNSPort (this crate's
//! `TorSupervisor`), the nftables redirect pointing at it
//! (`anonet-leakguard::TransparentRedirect`), and the radical kill switch
//! as a fail-safe for anything that isn't TCP/DNS or somehow doesn't get
//! redirected (`anonet-leakguard::KillSwitch::Radical`). None of the
//! pieces need to know about each other; this is just the orchestration
//! for one user-facing action (the dashboard's `t` key).

use anyhow::Result;
use anonet_leakguard::{KillSwitch, TransparentRedirect, current_uid};
use anonet_telemetry::Reporter;
use tokio::sync::Mutex;

use crate::{TorPorts, TorSupervisor};

pub struct FullAnonController {
    supervisor: Mutex<TorSupervisor>,
    ports: TorPorts,
    telemetry: Reporter,
}

impl FullAnonController {
    pub fn new(telemetry: Reporter) -> Self {
        let ports = TorPorts::default();
        Self {
            supervisor: Mutex::new(TorSupervisor::new(ports)),
            ports,
            telemetry,
        }
    }

    pub async fn is_running(&self) -> bool {
        self.supervisor.lock().await.is_running()
    }

    /// Starts the supervised tor process, waits for it to bootstrap, then
    /// applies the nftables redirect and radical kill switch. Can take a
    /// while (tor bootstrap + two sets of nftables rules) — callers should
    /// not block a UI thread on this.
    pub async fn enable(&self) -> Result<()> {
        let anonet_uid = current_uid().await?;

        {
            let mut supervisor = self.supervisor.lock().await;
            crate::start(&mut supervisor, self.telemetry.clone()).await?;
        }

        let redirect = TransparentRedirect {
            anonet_uid,
            trans_port: self.ports.trans_port,
            dns_port: self.ports.dns_port,
        };
        if let Err(err) = redirect.enable().await {
            self.supervisor.lock().await.stop().await;
            return Err(err);
        }

        let radical = KillSwitch::Radical { anonet_uid };
        if let Err(err) = radical.enable().await {
            let _ = redirect.disable().await;
            self.supervisor.lock().await.stop().await;
            return Err(err);
        }

        self.telemetry.update(|s| s.transparent_enabled = true);
        Ok(())
    }

    /// Tears down all three pieces. Best-effort and idempotent — safe to
    /// call even if `enable` partially failed or was never called.
    pub async fn disable(&self) {
        let anonet_uid = current_uid().await.unwrap_or(0);
        let redirect = TransparentRedirect {
            anonet_uid,
            trans_port: self.ports.trans_port,
            dns_port: self.ports.dns_port,
        };
        let _ = redirect.disable().await;
        let _ = KillSwitch::Radical { anonet_uid }.disable().await;
        self.supervisor.lock().await.stop().await;
        self.telemetry.update(|s| s.transparent_enabled = false);
    }
}
