//! nftables-based kill switches. Two independent, separately-toggleable
//! rulesets, each in its own dedicated table so enabling/disabling one
//! never touches the other or any pre-existing firewall rules on the
//! machine:
//!
//! - **Scoped** (`anonet_ks_scoped`): confines one specific UID (the
//!   process you actually want to force through anonet, e.g. a browser)
//!   to loopback only. That process can still reach the local SOCKS/DNS-shim
//!   ports; every other destination is dropped. Everything else on the
//!   machine is completely unaffected.
//! - **Radical** (`anonet_ks_system`): drops *all* non-loopback egress on
//!   the machine except the anonet process's own UID. This is the
//!   Whonix-gateway-style "nothing leaves except through Tor" mode — it
//!   will break every other app's network access while enabled, which is
//!   the point, but also means it's easy to lock yourself out of normal
//!   connectivity if you forget it's on.
//!
//! Both require root (nftables rule changes do). Neither is applied
//! automatically by `anonet run`; both are explicit, separately-invoked
//! actions.

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const SCOPED_TABLE: &str = "anonet_ks_scoped";
const SYSTEM_TABLE: &str = "anonet_ks_system";

#[derive(Debug, Clone, Copy)]
pub enum KillSwitch {
    /// Confine `protect_uid` to loopback only.
    Scoped { protect_uid: u32 },
    /// Drop all non-loopback egress except `anonet_uid`.
    Radical { anonet_uid: u32 },
}

impl KillSwitch {
    fn table(&self) -> &'static str {
        match self {
            KillSwitch::Scoped { .. } => SCOPED_TABLE,
            KillSwitch::Radical { .. } => SYSTEM_TABLE,
        }
    }

    fn ruleset(&self) -> String {
        match self {
            KillSwitch::Scoped { protect_uid } => format!(
                "table inet {SCOPED_TABLE} {{\n\
                 \tchain output {{\n\
                 \t\ttype filter hook output priority 0; policy accept;\n\
                 \t\tmeta skuid {protect_uid} oif lo accept\n\
                 \t\tmeta skuid {protect_uid} ip daddr 127.0.0.1 accept\n\
                 \t\tmeta skuid {protect_uid} ip6 daddr ::1 accept\n\
                 \t\tmeta skuid {protect_uid} counter drop\n\
                 \t}}\n\
                 }}\n"
            ),
            KillSwitch::Radical { anonet_uid } => format!(
                "table inet {SYSTEM_TABLE} {{\n\
                 \tchain output {{\n\
                 \t\ttype filter hook output priority 0; policy accept;\n\
                 \t\toif lo accept\n\
                 \t\tmeta skuid {anonet_uid} accept\n\
                 \t\tcounter drop\n\
                 \t}}\n\
                 }}\n"
            ),
        }
    }

    /// Applies this kill switch's ruleset. Requires root.
    pub async fn enable(&self) -> Result<()> {
        run_nft_stdin(&self.ruleset())
            .await
            .with_context(|| format!("failed to enable kill switch (table {})", self.table()))
    }

    /// Removes this kill switch's table, if present. Idempotent: disabling
    /// an already-disabled kill switch is not an error.
    pub async fn disable(&self) -> Result<()> {
        let script = format!("delete table inet {}\n", self.table());
        match run_nft_stdin(&script).await {
            Ok(()) => Ok(()),
            Err(err) if err.to_string().contains("No such file or directory") => Ok(()),
            Err(err) => Err(err).with_context(|| format!("failed to disable kill switch (table {})", self.table())),
        }
    }

    /// `Ok(true)`/`Ok(false)` when we could actually tell; `Err` when `nft`
    /// couldn't answer at all (e.g. no permission to read netlink state) —
    /// callers must not conflate that with "disabled".
    pub async fn is_enabled(&self) -> Result<bool> {
        let output = Command::new("nft")
            .args(["list", "table", "inet", self.table()])
            .output()
            .await
            .context("failed to run `nft list table`")?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such file or directory") {
            // The table genuinely doesn't exist: this kill switch is off.
            Ok(false)
        } else {
            bail!("nft could not report table status: {}", stderr.trim());
        }
    }
}

/// Reads the current process's real UID via `id -u`, so `anonet` doesn't
/// need to depend on a libc/nix crate just for one syscall's worth of info.
pub async fn current_uid() -> Result<u32> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .await
        .context("failed to run `id -u`")?;
    if !output.status.success() {
        bail!("`id -u` exited with {}", output.status);
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .context("`id -u` did not print a plain integer")
}

async fn run_nft_stdin(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn `nft` (is nftables installed?)")?;

    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())
        .await
        .context("failed to write ruleset to `nft` stdin")?;

    let output = child
        .wait_with_output()
        .await
        .context("failed waiting for `nft` to exit")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nft failed ({}): {}", output.status, stderr.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_ruleset_only_allows_loopback_for_that_uid() {
        let ruleset = KillSwitch::Scoped { protect_uid: 1000 }.ruleset();
        assert!(ruleset.contains("table inet anonet_ks_scoped"));
        assert!(ruleset.contains("meta skuid 1000 oif lo accept"));
        assert!(ruleset.contains("meta skuid 1000 counter drop"));
        // Must not accidentally scope by the wrong uid or drop unconditionally.
        assert!(!ruleset.contains("meta skuid 1000 accept\n\t\tcounter drop"));
    }

    #[test]
    fn radical_ruleset_allows_only_lo_and_anonet_uid() {
        let ruleset = KillSwitch::Radical { anonet_uid: 1000 }.ruleset();
        assert!(ruleset.contains("table inet anonet_ks_system"));
        assert!(ruleset.contains("oif lo accept"));
        assert!(ruleset.contains("meta skuid 1000 accept"));
        assert!(ruleset.trim_end().ends_with("counter drop\n\t}\n}"));
    }

    #[test]
    fn table_names_are_distinct() {
        assert_ne!(
            KillSwitch::Scoped { protect_uid: 1 }.table(),
            KillSwitch::Radical { anonet_uid: 1 }.table()
        );
    }
}
