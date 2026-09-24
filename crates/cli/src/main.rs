mod instance_lock;
mod status_server;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use anonet_bridges::{BridgeCoordinator, BridgeManager, TransportBinary};
use anonet_core::{AnonCore, CoreHandle};
use anonet_leakguard::{DnsShimController, KillSwitch, current_uid};
use anonet_socks::{ListenerConfig, SocksServer};
use anonet_transparent::FullAnonController;
use clap::{Args, Parser, Subcommand, ValueEnum};

/// `anonet` with no arguments boots straight into the live dashboard with
/// default settings — like `htop`/`btop`/`k9s`, not like a daemon you have
/// to remember a flag to actually see. `anonet run ...` is the same thing,
/// spelled out explicitly (useful in scripts/docs); `--headless` opts back
/// out to a plain log stream for systemd units and the like.
#[derive(Parser)]
#[command(name = "anonet", version, about = "Rust orchestration layer on top of Tor")]
struct Cli {
    #[command(flatten)]
    run: RunArgs,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Args, Clone)]
struct RunArgs {
    #[arg(long, default_value = "127.0.0.1:9450")]
    bind: SocketAddr,

    /// A torrc-style `Bridge ...` line. Repeatable; tried in order until
    /// one passes its health check. More can be added live from the
    /// dashboard (`a` key) once running. If the line names a pluggable
    /// transport (e.g. `obfs4`), its binary is auto-detected on disk —
    /// `--pt` is not required for known transports.
    #[arg(long = "bridge", value_name = "LINE")]
    bridges: Vec<String>,

    /// Registers a pluggable-transport binary at a specific path, as
    /// `protocol=/path/to/binary` (e.g. `obfs4=/usr/bin/obfs4proxy`).
    /// Repeatable. Only needed to override auto-detection (a non-standard
    /// install location) or for a transport anonet doesn't know how to
    /// find on its own.
    #[arg(long = "pt", value_name = "PROTOCOL=PATH")]
    pluggable_transports: Vec<String>,

    /// Seconds to wait for a bridge health check before trying the next one.
    #[arg(long, default_value_t = 30)]
    bridge_timeout_secs: u64,

    /// Also run a DNS-over-UDP shim on this address, resolving every
    /// query via Tor. For apps that resolve names themselves instead of
    /// using SOCKS5 hostname CONNECT.
    #[arg(long = "dns-shim", value_name = "ADDR")]
    dns_shim: Option<SocketAddr>,

    /// Seconds between background health checks of the active bridge
    /// once running.
    #[arg(long, default_value_t = 60)]
    bridge_check_interval_secs: u64,

    /// Consecutive failed health checks before searching for a
    /// replacement bridge.
    #[arg(long, default_value_t = 3)]
    bridge_failure_threshold: u32,

    /// Skip the live dashboard and just log to stdout — for scripts,
    /// systemd units, or anywhere else nothing will be watching a
    /// terminal. The dashboard is the default: this is meant to be run and
    /// watched, not launched blind.
    #[arg(long)]
    headless: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Explicit spelling of the default action (bootstrap Tor + SOCKS front end).
    Run(RunArgs),

    /// Manage the nftables kill switches. Requires root.
    Killswitch {
        #[command(subcommand)]
        action: KillswitchAction,
    },

    /// Report a running `anonet run` instance's live status (SOCKS
    /// connections, active bridge, DNS shim, full anonymization) without
    /// opening the dashboard — for scripts and systemd health checks.
    Status,
}

#[derive(Clone, Copy, ValueEnum)]
enum KsMode {
    /// Confine one UID to loopback only (protects that one app).
    Scoped,
    /// Drop all non-loopback egress except anonet's own UID (whole-machine).
    Radical,
}

#[derive(Subcommand)]
enum KillswitchAction {
    /// Apply a kill switch.
    Enable {
        #[arg(long, value_enum)]
        mode: KsMode,

        /// UID to confine to loopback. Required for --mode scoped.
        #[arg(long)]
        protect_uid: Option<u32>,

        /// Auto-disable after this many seconds (or on Ctrl+C). Strongly
        /// recommended for --mode radical, since it can otherwise cut off
        /// this machine's normal network access until you remember to run
        /// `killswitch disable` yourself.
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    /// Remove a kill switch (idempotent: fine to call if it's already off).
    Disable {
        #[arg(long, value_enum)]
        mode: KsMode,
    },
    /// Report whether each kill switch is currently active.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let run_args = match cli.command {
        Some(Command::Run(args)) => args,
        Some(Command::Killswitch { action }) => {
            init_tracing(false)?;
            return killswitch(action).await;
        }
        Some(Command::Status) => return status().await,
        None => cli.run,
    };

    let _instance_guard = instance_lock::acquire()?;

    let tui_mode = !run_args.headless;
    init_tracing(tui_mode)?;
    run(run_args).await
}

fn anonet_log_path() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("anonet")
        .join("anonet.log")
}

const LOG_ROTATE_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;

/// The dashboard runs for long, unattended stretches with logging always
/// on, and nothing else ever truncates `anonet.log` — left alone it grows
/// forever. A single rotation at startup (checked each time the dashboard
/// launches, not on a timer mid-run) is enough to bound it in practice
/// without pulling in a rolling-file-appender dependency for what's a
/// one-line problem: once a session's log passes the threshold, the next
/// launch starts a fresh file and keeps one previous generation around.
fn rotate_log_if_large(path: &std::path::Path, max_bytes: u64) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.len() > max_bytes {
        let rotated = path.with_extension("log.1");
        let _ = std::fs::rename(path, rotated);
    }
}

/// Logs go to stdout normally. With the dashboard running, stdout belongs
/// to it, so logs go to a file instead.
fn init_tracing(tui_mode: bool) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    if !tui_mode {
        tracing_subscriber::fmt().with_env_filter(filter).init();
        return Ok(());
    }

    let log_path = anonet_log_path();
    if let Some(dir) = log_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    rotate_log_if_large(&log_path, LOG_ROTATE_THRESHOLD_BYTES);
    let file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(file)
        .with_ansi(false)
        .init();
    eprintln!("logs going to {} (dashboard is using stdout)", log_path.display());
    Ok(())
}

async fn killswitch(action: KillswitchAction) -> Result<()> {
    match action {
        KillswitchAction::Enable {
            mode,
            protect_uid,
            ttl_secs,
        } => {
            let ks = match mode {
                KsMode::Scoped => {
                    let uid = protect_uid
                        .ok_or_else(|| anyhow!("--mode scoped requires --protect-uid <uid>"))?;
                    KillSwitch::Scoped { protect_uid: uid }
                }
                KsMode::Radical => {
                    let uid = current_uid().await?;
                    tracing::info!(anonet_uid = uid, "radical kill switch will exempt this process's own UID");
                    KillSwitch::Radical { anonet_uid: uid }
                }
            };

            let ttl_secs = ttl_secs.or(match mode {
                KsMode::Radical => Some(300),
                KsMode::Scoped => None,
            });

            ks.enable().await?;
            tracing::info!(mode = mode_label(mode), "kill switch enabled");

            match ttl_secs {
                None => {
                    println!("Kill switch enabled with no TTL. Run `anonet killswitch disable --mode {}` to remove it.", mode_label(mode));
                    Ok(())
                }
                Some(secs) => {
                    println!(
                        "Kill switch enabled for up to {secs}s (Ctrl+C disables it immediately)."
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(secs)) => {
                            tracing::info!("TTL elapsed, disabling kill switch");
                        }
                        _ = tokio::signal::ctrl_c() => {
                            tracing::info!("Ctrl+C received, disabling kill switch");
                        }
                    }
                    ks.disable().await?;
                    println!("Kill switch disabled.");
                    Ok(())
                }
            }
        }
        KillswitchAction::Disable { mode } => {
            let ks = match mode {
                KsMode::Scoped => KillSwitch::Scoped { protect_uid: 0 },
                KsMode::Radical => KillSwitch::Radical { anonet_uid: 0 },
            };
            ks.disable().await?;
            println!("Kill switch ({}) disabled.", mode_label(mode));
            Ok(())
        }
        KillswitchAction::Status => {
            let scoped = KillSwitch::Scoped { protect_uid: 0 }.is_enabled().await?;
            let radical = KillSwitch::Radical { anonet_uid: 0 }.is_enabled().await?;
            println!("scoped:  {}", if scoped { "ENABLED" } else { "disabled" });
            println!("radical: {}", if radical { "ENABLED" } else { "disabled" });
            Ok(())
        }
    }
}

async fn status() -> Result<()> {
    let path = status_server::socket_path();
    let mut stream = tokio::net::UnixStream::connect(&path).await.with_context(|| {
        format!(
            "couldn't connect to {} — is `anonet run` currently running as this user?",
            path.display()
        )
    })?;
    let mut buf = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut buf).await?;
    print!("{buf}");
    Ok(())
}

fn mode_label(mode: KsMode) -> &'static str {
    match mode {
        KsMode::Scoped => "scoped",
        KsMode::Radical => "radical",
    }
}

async fn run(args: RunArgs) -> Result<()> {
    let RunArgs {
        bind,
        bridges,
        pluggable_transports,
        bridge_timeout_secs,
        dns_shim,
        bridge_check_interval_secs,
        bridge_failure_threshold,
        headless,
    } = args;

    let (telemetry, health_rx) = anonet_telemetry::channel();

    // Log every telemetry change, so live health/failover state is visible
    // as tracing output even without the dashboard.
    let mut log_rx = health_rx.clone();
    tokio::spawn(async move {
        while log_rx.changed().await.is_ok() {
            let status = log_rx.borrow().clone();
            tracing::info!(
                active_bridge = ?status.active_bridge_line,
                consecutive_failures = status.consecutive_failures,
                total_switches = status.total_switches,
                "health status updated"
            );
        }
    });

    let transports = pluggable_transports
        .iter()
        .map(|spec| parse_pt_spec(spec))
        .collect::<Result<Vec<_>>>()?;
    let manager = Arc::new(BridgeManager::new(transports));
    for line in &bridges {
        manager.add_bridge_line(line)?;
    }
    telemetry.update(|s| s.seed_candidates(&manager.all_candidates()));

    let mut active_bridge_idx: Option<usize> = None;
    let core = if manager.candidate_count() == 0 {
        tracing::info!("bootstrapping Tor client (this can take a few seconds)");
        let core = bootstrap_with_progress("bootstrapping Tor", AnonCore::bootstrap()).await?;
        tracing::info!("Tor client bootstrapped");
        core
    } else {
        tracing::info!(count = manager.candidate_count(), "checking configured bridges");
        let telemetry_for_scan = telemetry.clone();
        match manager
            .find_healthy_config_reporting(Duration::from_secs(bridge_timeout_secs), |idx, result| {
                telemetry_for_scan.update(|s| {
                    s.record_candidate_result(
                        idx,
                        &result.candidate_line,
                        result.success,
                        result.latency.as_millis() as u64,
                    )
                });
            })
            .await
        {
            Ok((idx, config)) => {
                tracing::info!(candidate = idx, "bridge healthy, bootstrapping real client through it");
                active_bridge_idx = Some(idx);
                bootstrap_with_progress("bootstrapping Tor via bridge", AnonCore::bootstrap_with(config)).await?
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "no configured bridge passed its health check; falling back to a direct (bridge-less) Tor connection"
                );
                bootstrap_with_progress("bootstrapping Tor (direct fallback)", AnonCore::bootstrap()).await?
            }
        }
    };

    let handle = Arc::new(CoreHandle::new(core));
    let check_now = Arc::new(tokio::sync::Notify::new());

    // Always running, even with zero bridges configured at startup: this is
    // what lets the dashboard's "add a bridge" action take effect without a
    // restart, not just automatic failover among pre-configured ones.
    let coordinator = Arc::new(BridgeCoordinator::new(
        Arc::clone(&manager),
        Arc::clone(&handle),
        telemetry.clone(),
        active_bridge_idx,
        Duration::from_secs(bridge_check_interval_secs),
        Duration::from_secs(bridge_timeout_secs),
        bridge_failure_threshold,
        Arc::clone(&check_now),
    ));
    {
        let coordinator = Arc::clone(&coordinator);
        tokio::spawn(async move {
            coordinator.run().await;
        });
    }

    let dns_controller = Arc::new(DnsShimController::new(Arc::clone(&handle)));
    if let Some(dns_bind) = dns_shim {
        dns_controller.start(dns_bind)?;
    }

    let full_anon = Arc::new(FullAnonController::new(telemetry.clone()));

    {
        let status_health_rx = health_rx.clone();
        let status_dns_controller = Arc::clone(&dns_controller);
        tokio::spawn(async move {
            if let Err(err) = status_server::serve(bind, status_health_rx, status_dns_controller).await {
                tracing::warn!(error = %err, "status socket server stopped");
            }
        });
    }

    let server = SocksServer::new(Arc::clone(&handle), telemetry.clone());
    if headless {
        server.run(ListenerConfig { bind }).await
    } else {
        // Bind synchronously, before the dashboard ever renders "SOCKS5:
        // UP" — a bind failure (e.g. a port a stale previous instance was
        // still holding, before instance_lock existed) must be a fatal,
        // immediately visible startup error, not something a background
        // task discovers after the fact.
        let listener = server.bind(ListenerConfig { bind }).await?;
        let services = anonet_tui::ServicesInfo { socks_addr: bind };
        tokio::spawn(async move {
            if let Err(err) = server.serve(listener).await {
                tracing::error!(error = %err, "SOCKS5 server stopped");
            }
        });
        anonet_tui::run(
            handle,
            health_rx,
            check_now,
            anonet_log_path(),
            services,
            coordinator,
            dns_controller,
            full_anon,
        )
        .await
    }
}

/// Bootstrapping Tor can take anywhere from a few seconds to (rarely,
/// under bad network conditions) over a minute, and this always runs
/// *before* the dashboard takes over the screen — so without some visible
/// sign of life, a slow bootstrap looks indistinguishable from a hang.
/// Prints directly to stdout (not through `tracing`, which is already
/// redirected to a log file by the time the dashboard runs) every 5s
/// until `fut` resolves.
async fn bootstrap_with_progress(
    label: &str,
    fut: impl std::future::Future<Output = Result<AnonCore>>,
) -> Result<AnonCore> {
    println!("{label}...");
    tokio::pin!(fut);
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    ticker.tick().await; // the first tick fires immediately; skip it
    let start = std::time::Instant::now();
    loop {
        tokio::select! {
            res = &mut fut => return res,
            _ = ticker.tick() => {
                println!("{label}... still working ({}s elapsed)", start.elapsed().as_secs());
            }
        }
    }
}

fn parse_pt_spec(spec: &str) -> Result<TransportBinary> {
    let (protocol, path) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("--pt must be formatted as protocol=/path/to/binary, got '{spec}'"))?;
    if protocol.is_empty() || path.is_empty() {
        return Err(anyhow!("--pt protocol and path must both be non-empty (got '{spec}')"));
    }
    Ok(TransportBinary::new(protocol, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_log_if_large_renames_when_over_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("anonet.log");
        std::fs::write(&log, vec![0u8; 100]).unwrap();

        rotate_log_if_large(&log, 50);

        assert!(!log.exists(), "oversized log should have been rotated away");
        assert!(dir.path().join("anonet.log.1").exists());
    }

    #[test]
    fn rotate_log_if_large_leaves_small_logs_alone() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("anonet.log");
        std::fs::write(&log, vec![0u8; 10]).unwrap();

        rotate_log_if_large(&log, 50);

        assert!(log.exists());
        assert!(!dir.path().join("anonet.log.1").exists());
    }

    #[test]
    fn rotate_log_if_large_is_a_noop_when_file_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("anonet.log");
        rotate_log_if_large(&log, 50); // must not panic
        assert!(!log.exists());
    }
}
