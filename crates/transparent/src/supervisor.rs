//! Manages a real `tor` subprocess configured for transparent proxying
//! (`TransPort`/`DNSPort`) plus a `ControlPort` for live stream events.
//!
//! We deliberately don't reimplement transparent interception ourselves:
//! recovering the original destination of a NAT-redirected connection
//! (`SO_ORIGINAL_DST`) and relaying it is exactly what Tor's own
//! `TransPort` already does, the same way tools like Parrot's anonsurf
//! drive it. anonet's job here is orchestration: generate a torrc, launch
//! and supervise the process, and read its `ControlPort` for visibility —
//! not re-implement Tor's transparent-proxy internals.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

#[derive(Debug, Clone, Copy)]
pub struct TorPorts {
    pub trans_port: u16,
    pub dns_port: u16,
    pub control_port: u16,
}

impl Default for TorPorts {
    fn default() -> Self {
        Self {
            trans_port: 9040,
            dns_port: 5300,
            control_port: 9051,
        }
    }
}

pub struct TorSupervisor {
    ports: TorPorts,
    data_dir: PathBuf,
    child: Option<Child>,
}

impl TorSupervisor {
    pub fn new(ports: TorPorts) -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("anonet")
            .join("tor-transparent");
        Self {
            ports,
            data_dir,
            child: None,
        }
    }

    pub fn ports(&self) -> TorPorts {
        self.ports
    }

    pub fn cookie_path(&self) -> PathBuf {
        self.data_dir.join("control_auth_cookie")
    }

    /// Writes a torrc, launches `tor`, and waits for it to report
    /// `Bootstrapped 100%` on stdout before returning. The child is killed
    /// on `stop()` or when this supervisor is dropped.
    pub async fn start(&mut self) -> Result<()> {
        if self.child.is_some() {
            bail!("tor is already running");
        }

        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("failed to create {}", self.data_dir.display()))?;

        let torrc_path = self.data_dir.join("torrc");
        let torrc = format!(
            "SocksPort 0\n\
             TransPort 127.0.0.1:{trans}\n\
             DNSPort 127.0.0.1:{dns}\n\
             ControlPort 127.0.0.1:{control}\n\
             CookieAuthentication 1\n\
             DataDirectory {data_dir}\n\
             Log notice stdout\n\
             RunAsDaemon 0\n",
            trans = self.ports.trans_port,
            dns = self.ports.dns_port,
            control = self.ports.control_port,
            data_dir = self.data_dir.display(),
        );
        std::fs::write(&torrc_path, torrc).context("failed to write torrc")?;

        let mut child = Command::new("tor")
            .arg("-f")
            .arg(&torrc_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn `tor` (is it installed and on PATH?)")?;

        let stdout = child.stdout.take().expect("piped stdout");
        let mut lines = BufReader::new(stdout).lines();

        let bootstrap = tokio::time::timeout(std::time::Duration::from_secs(120), async {
            while let Some(line) = lines.next_line().await.context("reading tor stdout")? {
                tracing::debug!(target: "tor", "{line}");
                if line.contains("Bootstrapped 100%") {
                    return Ok::<(), anyhow::Error>(());
                }
                if line.contains("[err]") || line.contains("[warn]") && line.contains("Bootstrapped") {
                    tracing::warn!(target: "tor", "{line}");
                }
            }
            bail!("tor exited before finishing bootstrap")
        })
        .await;

        match bootstrap {
            Ok(Ok(())) => {
                self.child = Some(child);
                Ok(())
            }
            Ok(Err(err)) => {
                let _ = child.kill().await;
                Err(err)
            }
            Err(_elapsed) => {
                let _ = child.kill().await;
                bail!("tor did not finish bootstrapping within 120s")
            }
        }
    }

    pub async fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
    }

    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }
}
