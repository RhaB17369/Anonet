//! Single-instance guard: refuses to start a second `anonet run` on top of
//! one that's already alive, instead of silently colliding on the SOCKS5
//! port and the arti state lock 30-90s into a Tor bootstrap (which is
//! exactly what happened without this — a previous instance that outlived
//! its terminal session kept the port, and the next launch only found out
//! at the very end, deep in an unrelated-looking error).

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

fn pid_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("anonet")
        .join("anonet.pid")
}

fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Holds the PID file for the process's lifetime; removes it on drop so a
/// clean exit (or a panic, which still unwinds through this) never leaves
/// a stale lock behind.
pub struct InstanceGuard {
    path: PathBuf,
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Checks for a still-alive previous instance and, if found, kills it
/// (SIGTERM, then SIGKILL if it doesn't exit within 5s) before taking over
/// — automatically, every time, since a previous instance outliving its
/// terminal is exactly the failure mode this guards against, and making
/// the user remember a flag just reintroduces the same trap. Always writes
/// a fresh PID file for this process once the port/lock is free.
pub fn acquire() -> Result<InstanceGuard> {
    let path = pid_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }

    if let Ok(contents) = std::fs::read_to_string(&path) {
        if let Ok(old_pid) = contents.trim().parse::<u32>() {
            if process_alive(old_pid) {
                eprintln!("a previous anonet instance is still running (PID {old_pid}); stopping it...");
                // Target the process group (negative PID), not just the
                // single PID: if that instance had full anonymization on,
                // its supervised `tor` child shares its process group, and
                // we want that stopped too, not left as a fresh orphan.
                let _ = std::process::Command::new("kill")
                    .arg("-TERM")
                    .arg(format!("-{old_pid}"))
                    .status();
                for _ in 0..50 {
                    if !process_alive(old_pid) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                if process_alive(old_pid) {
                    eprintln!("PID {old_pid} ignored SIGTERM; sending SIGKILL...");
                    let _ = std::process::Command::new("kill")
                        .arg("-KILL")
                        .arg(format!("-{old_pid}"))
                        .status();
                    for _ in 0..20 {
                        if !process_alive(old_pid) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    if process_alive(old_pid) {
                        bail!("PID {old_pid} would not die even after SIGKILL; stop it manually and retry.");
                    }
                }
                eprintln!("previous instance stopped, continuing");
            }
        }
    }

    std::fs::write(&path, std::process::id().to_string())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(InstanceGuard { path })
}
