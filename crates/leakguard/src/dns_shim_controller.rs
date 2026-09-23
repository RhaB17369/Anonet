//! Lets a caller (the TUI) start and stop the DNS shim at runtime, instead
//! of it only ever being fixed at process launch by `--dns-shim`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};
use anonet_core::CoreHandle;
use tokio::task::JoinHandle;

use crate::DnsShim;

pub struct DnsShimController {
    core: Arc<CoreHandle>,
    running: Mutex<Option<(SocketAddr, JoinHandle<()>)>>,
}

impl DnsShimController {
    pub fn new(core: Arc<CoreHandle>) -> Self {
        Self {
            core,
            running: Mutex::new(None),
        }
    }

    pub fn bound_addr(&self) -> Option<SocketAddr> {
        self.running.lock().expect("poisoned").as_ref().map(|(addr, _)| *addr)
    }

    pub fn start(&self, addr: SocketAddr) -> Result<()> {
        let mut running = self.running.lock().expect("poisoned");
        if running.is_some() {
            bail!("DNS shim is already running");
        }
        let shim = DnsShim::new(Arc::clone(&self.core));
        let handle = tokio::spawn(async move {
            if let Err(err) = shim.run(addr).await {
                tracing::error!(error = %err, "DNS shim stopped");
            }
        });
        *running = Some((addr, handle));
        Ok(())
    }

    pub fn stop(&self) -> bool {
        let mut running = self.running.lock().expect("poisoned");
        match running.take() {
            Some((_, handle)) => {
                handle.abort();
                true
            }
            None => false,
        }
    }
}
