//! nftables NAT rules that redirect TCP (and UDP port 53) traffic to the
//! supervised `tor` process's `TransPort`/`DNSPort`, for every UID except
//! anonet's own — the actual "everything goes through Tor automatically"
//! mechanism. Meant to be paired with `KillSwitch::Radical` as a fail-safe:
//! the redirect handles TCP and DNS; anything that isn't TCP (or somehow
//! isn't redirected) still gets dropped by the radical kill switch's DROP
//! rule rather than leaking, since redirected traffic becomes
//! loopback-destined before it would ever reach that rule.
//!
//! Local/private destinations (loopback, RFC1918 ranges) and port 22 are
//! excluded so LAN traffic and SSH management sessions keep working
//! normally instead of being forced through Tor (which can't reach private
//! addresses anyway).

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const TABLE: &str = "anonet_transparent";

#[derive(Debug, Clone, Copy)]
pub struct TransparentRedirect {
    pub anonet_uid: u32,
    pub trans_port: u16,
    pub dns_port: u16,
}

impl TransparentRedirect {
    fn ruleset(&self) -> String {
        let Self { anonet_uid, trans_port, dns_port } = *self;
        let skip_rules = format!(
            "\t\tmeta skuid {anonet_uid} return\n\
             \t\tip daddr {{ 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} return\n\
             \t\ttcp dport 22 return\n"
        );
        format!(
            "table inet {TABLE} {{\n\
             \tchain prerouting {{\n\
             \t\ttype nat hook prerouting priority -100; policy accept;\n\
             {skip_rules}\
             \t\tudp dport 53 redirect to :{dns_port}\n\
             \t\tmeta l4proto tcp redirect to :{trans_port}\n\
             \t}}\n\
             \tchain output {{\n\
             \t\ttype nat hook output priority -100; policy accept;\n\
             {skip_rules}\
             \t\tudp dport 53 redirect to :{dns_port}\n\
             \t\tmeta l4proto tcp redirect to :{trans_port}\n\
             \t}}\n\
             }}\n"
        )
    }

    pub async fn enable(&self) -> Result<()> {
        run_nft_stdin(&self.ruleset())
            .await
            .context("failed to enable transparent redirect")
    }

    pub async fn disable(&self) -> Result<()> {
        let script = format!("delete table inet {TABLE}\n");
        match run_nft_stdin(&script).await {
            Ok(()) => Ok(()),
            Err(err) if err.to_string().contains("No such file or directory") => Ok(()),
            Err(err) => Err(err).context("failed to disable transparent redirect"),
        }
    }

    pub async fn is_enabled(&self) -> Result<bool> {
        let output = Command::new("nft")
            .args(["list", "table", "inet", TABLE])
            .output()
            .await
            .context("failed to run `nft list table`")?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such file or directory") {
            Ok(false)
        } else {
            anyhow::bail!("nft could not report table status: {}", stderr.trim());
        }
    }
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

    let output = child.wait_with_output().await.context("failed waiting for `nft` to exit")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft failed ({}): {}", output.status, stderr.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_exempts_anonet_uid_and_local_ranges() {
        let r = TransparentRedirect { anonet_uid: 1000, trans_port: 9040, dns_port: 5300 };
        let ruleset = r.ruleset();
        assert!(ruleset.contains("table inet anonet_transparent"));
        assert!(ruleset.contains("meta skuid 1000 return"));
        assert!(ruleset.contains("192.168.0.0/16"));
        assert!(ruleset.contains("tcp dport 22 return"));
        assert!(ruleset.contains("redirect to :9040"));
        assert!(ruleset.contains("redirect to :5300"));
    }
}
