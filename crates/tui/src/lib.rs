//! Live status dashboard: bridge/circuit health with a latency sparkline,
//! the full bridge-candidate pool's last known status, active isolation
//! buckets, kill switch status, and a tail of the log file — all read
//! from the same `CoreHandle` and `anonet-telemetry` channel the rest of
//! the app uses, no separate IPC. This is the default UI (`anonet` with
//! no flags); `--headless` skips it.
//!
//! Every feature the process has is reachable live from here, not just at
//! launch:
//! - `a`: type in a new bridge line and try it live, via
//!   `anonet-bridges::BridgeCoordinator::try_add_bridge` — the same
//!   activate-if-healthy path automatic failover uses, just triggered
//!   manually instead of by the background monitor.
//! - `c`: force an immediate health check of the active bridge instead of
//!   waiting out the rest of the check interval.
//! - `n`: toggle the DNS shim on (asks for a bind address) or off.
//! - `k`: enable a kill switch (scoped asks for the UID to confine;
//!   radical asks for confirmation, since it blocks the whole machine's
//!   non-loopback traffic — it auto-reverts after 5 minutes regardless,
//!   so a confirmed mistake here is never permanent).
//! - `d`: disable a kill switch — always a safe, one-key action.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use anonet_bridges::BridgeCoordinator;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use futures_util::StreamExt;
use ratatui::Frame;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table};
use tokio::sync::{Notify, watch};

use anonet_core::CoreHandle;
use anonet_leakguard::{DnsShimController, KillSwitch, current_uid};
use anonet_telemetry::HealthStatus;

const LOG_TAIL_LINES: usize = 10;

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    }
}

#[derive(Default)]
struct KillSwitchView {
    scoped: Option<bool>,
    radical: Option<bool>,
}

/// Static info about which services this process started with — doesn't
/// change over the run's lifetime, unlike everything in `HealthStatus`.
#[derive(Clone)]
pub struct ServicesInfo {
    pub socks_addr: SocketAddr,
}

enum Mode {
    Normal,
    ConfirmDisable,
    AddBridge { buffer: String },
    KillSwitchMenu,
    EnterScopedUid { buffer: String },
    ConfirmRadicalEnable,
    EnterDnsAddr { buffer: String },
}

/// The context-sensitive, always-visible list of keys available right now
/// — separate from `status_line`, which holds one-off results ("bridge
/// added") that would otherwise bury the help text the moment something
/// happens. This is what makes the available actions visible live rather
/// than something you have to already know.
fn help_text(mode: &Mode) -> &'static str {
    match mode {
        Mode::Normal => "q quit   a add bridge   c check bridge now   n toggle DNS shim   k enable a kill switch   d disable a kill switch",
        Mode::ConfirmDisable => "s disable scoped   r disable radical   Esc cancel",
        Mode::AddBridge { .. } => "type a Bridge line   Enter submit   Esc cancel",
        Mode::KillSwitchMenu => "s enable scoped (asks for a UID)   r enable radical (asks to confirm)   Esc cancel",
        Mode::EnterScopedUid { .. } => "type the UID to confine to loopback   Enter apply   Esc cancel",
        Mode::ConfirmRadicalEnable => "y confirm (blocks ALL non-loopback traffic for 5 min, auto-reverts)   Esc cancel",
        Mode::EnterDnsAddr { .. } => "type a bind address (e.g. 127.0.0.1:9535)   Enter apply   Esc cancel",
    }
}

struct AppState {
    started_at: Instant,
    services: ServicesInfo,
    health: HealthStatus,
    isolation: Vec<(String, u32, Duration)>,
    killswitches: KillSwitchView,
    dns_shim_addr: Option<SocketAddr>,
    status_line: String,
    mode: Mode,
    log_tail: Vec<String>,
}

/// Runs the dashboard until the user quits (`q`/Esc). Takes over the
/// terminal (raw mode + alternate screen) for the duration and always
/// restores it on the way out, including on error.
///
/// `check_now` lets the `c` key wake `anonet-bridges::BridgeCoordinator`
/// early instead of waiting out the rest of its check interval.
/// `log_path` is tailed on every refresh tick for the log panel.
/// `coordinator` is what `a` (add a bridge live) calls into.
pub async fn run(
    core: Arc<CoreHandle>,
    mut health_rx: watch::Receiver<HealthStatus>,
    check_now: Arc<Notify>,
    log_path: PathBuf,
    services: ServicesInfo,
    coordinator: Arc<BridgeCoordinator>,
    dns_controller: Arc<DnsShimController>,
) -> Result<()> {
    enable_raw_mode()?;
    execute!(std::io::stdout(), EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut state = AppState {
        started_at: Instant::now(),
        services,
        health: health_rx.borrow().clone(),
        isolation: Vec::new(),
        killswitches: KillSwitchView::default(),
        dns_shim_addr: dns_controller.bound_addr(),
        status_line: String::new(),
        mode: Mode::Normal,
        log_tail: Vec::new(),
    };
    refresh_snapshot(&core, &log_path, &mut state).await;
    refresh_killswitch_status(&mut state).await;

    let mut events = EventStream::new();
    let mut refresh_tick = tokio::time::interval(Duration::from_secs(2));

    loop {
        terminal.draw(|frame| draw(frame, &state))?;

        tokio::select! {
            changed = health_rx.changed() => {
                if changed.is_ok() {
                    state.health = health_rx.borrow().clone();
                }
                // If the sender was dropped, just keep the dashboard usable
                // for inspection/quit — nothing more will arrive.
            }
            _ = refresh_tick.tick() => {
                refresh_snapshot(&core, &log_path, &mut state).await;
                refresh_killswitch_status(&mut state).await;
                state.dns_shim_addr = dns_controller.bound_addr();
            }
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        if handle_key(key.code, &mut state, &check_now, &coordinator, &dns_controller).await {
                            break;
                        }
                    }
                    Some(Err(err)) => {
                        state.status_line = format!("input error: {err}");
                    }
                    None => break,
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

async fn refresh_snapshot(core: &CoreHandle, log_path: &Path, state: &mut AppState) {
    let c = core.current().await;
    state.isolation = c.isolation_snapshot();
    state.isolation.sort_by(|a, b| a.0.cmp(&b.0));
    state.log_tail = tail_log(log_path, LOG_TAIL_LINES);
}

fn tail_log(path: &Path, n: usize) -> Vec<String> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].iter().map(|l| l.to_string()).collect()
}

async fn refresh_killswitch_status(state: &mut AppState) {
    state.killswitches.scoped = KillSwitch::Scoped { protect_uid: 0 }.is_enabled().await.ok();
    state.killswitches.radical = KillSwitch::Radical { anonet_uid: 0 }.is_enabled().await.ok();
}

/// Returns `true` if the app should quit.
async fn handle_key(
    code: KeyCode,
    state: &mut AppState,
    check_now: &Notify,
    coordinator: &Arc<BridgeCoordinator>,
    dns_controller: &Arc<DnsShimController>,
) -> bool {
    match &mut state.mode {
        Mode::ConfirmDisable => {
            match code {
                KeyCode::Char('s') => {
                    state.mode = Mode::Normal;
                    state.status_line = match (KillSwitch::Scoped { protect_uid: 0 }).disable().await {
                        Ok(()) => "scoped kill switch disabled".to_string(),
                        Err(err) => format!("failed to disable scoped kill switch: {err}"),
                    };
                    refresh_killswitch_status(state).await;
                }
                KeyCode::Char('r') => {
                    state.mode = Mode::Normal;
                    state.status_line = match (KillSwitch::Radical { anonet_uid: 0 }).disable().await {
                        Ok(()) => "radical kill switch disabled".to_string(),
                        Err(err) => format!("failed to disable radical kill switch: {err}"),
                    };
                    refresh_killswitch_status(state).await;
                }
                KeyCode::Esc => {
                    state.mode = Mode::Normal;
                    state.status_line = "cancelled".to_string();
                }
                _ => {}
            }
            return false;
        }
        Mode::AddBridge { buffer } => {
            match code {
                KeyCode::Enter => {
                    let line = buffer.clone();
                    state.mode = Mode::Normal;
                    if line.trim().is_empty() {
                        state.status_line = "cancelled (empty bridge line)".to_string();
                        return false;
                    }
                    state.status_line = "checking new bridge... (watch the candidates table)".to_string();
                    let coordinator = Arc::clone(coordinator);
                    tokio::spawn(async move {
                        // Result surfaces via the candidates table (and
                        // active_bridge_line on success) through the same
                        // telemetry channel the dashboard already watches —
                        // no separate return path needed.
                        let _ = coordinator.try_add_bridge(&line).await;
                    });
                }
                KeyCode::Esc => {
                    state.mode = Mode::Normal;
                    state.status_line = "cancelled".to_string();
                }
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) => {
                    buffer.push(c);
                }
                _ => {}
            }
            return false;
        }
        Mode::KillSwitchMenu => {
            match code {
                KeyCode::Char('s') => {
                    state.mode = Mode::EnterScopedUid { buffer: String::new() };
                }
                KeyCode::Char('r') => {
                    state.mode = Mode::ConfirmRadicalEnable;
                }
                KeyCode::Esc => {
                    state.mode = Mode::Normal;
                    state.status_line = "cancelled".to_string();
                }
                _ => {}
            }
            return false;
        }
        Mode::EnterScopedUid { buffer } => {
            match code {
                KeyCode::Enter => {
                    let typed = buffer.clone();
                    state.mode = Mode::Normal;
                    match typed.trim().parse::<u32>() {
                        Ok(uid) => {
                            state.status_line = match (KillSwitch::Scoped { protect_uid: uid }).enable().await {
                                Ok(()) => format!("scoped kill switch enabled, confining uid {uid} to loopback"),
                                Err(err) => format!("failed to enable scoped kill switch: {err}"),
                            };
                            refresh_killswitch_status(state).await;
                        }
                        Err(_) => {
                            state.status_line = format!("'{typed}' is not a valid UID, cancelled");
                        }
                    }
                }
                KeyCode::Esc => {
                    state.mode = Mode::Normal;
                    state.status_line = "cancelled".to_string();
                }
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    buffer.push(c);
                }
                _ => {}
            }
            return false;
        }
        Mode::ConfirmRadicalEnable => {
            match code {
                KeyCode::Char('y') => {
                    state.mode = Mode::Normal;
                    state.status_line = "enabling radical kill switch...".to_string();
                    tokio::spawn(async move {
                        let Ok(uid) = current_uid().await else {
                            return;
                        };
                        let ks = KillSwitch::Radical { anonet_uid: uid };
                        if ks.enable().await.is_ok() {
                            tokio::time::sleep(Duration::from_secs(300)).await;
                            let _ = ks.disable().await;
                        }
                    });
                }
                KeyCode::Esc => {
                    state.mode = Mode::Normal;
                    state.status_line = "cancelled".to_string();
                }
                _ => {}
            }
            return false;
        }
        Mode::EnterDnsAddr { buffer } => {
            match code {
                KeyCode::Enter => {
                    let typed = buffer.clone();
                    state.mode = Mode::Normal;
                    match typed.trim().parse::<SocketAddr>() {
                        Ok(addr) => {
                            state.status_line = match dns_controller.start(addr) {
                                Ok(()) => format!("DNS shim started on {addr}"),
                                Err(err) => format!("failed to start DNS shim: {err}"),
                            };
                            state.dns_shim_addr = dns_controller.bound_addr();
                        }
                        Err(_) => {
                            state.status_line = format!("'{typed}' is not a valid address (expected host:port)");
                        }
                    }
                }
                KeyCode::Esc => {
                    state.mode = Mode::Normal;
                    state.status_line = "cancelled".to_string();
                }
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) => {
                    buffer.push(c);
                }
                _ => {}
            }
            return false;
        }
        Mode::Normal => {}
    }

    match code {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        KeyCode::Char('c') => {
            check_now.notify_one();
            state.status_line = "requested an immediate bridge health check".to_string();
        }
        KeyCode::Char('a') => {
            state.mode = Mode::AddBridge { buffer: String::new() };
        }
        KeyCode::Char('n') => {
            if state.dns_shim_addr.is_some() {
                dns_controller.stop();
                state.dns_shim_addr = None;
                state.status_line = "DNS shim stopped".to_string();
            } else {
                state.mode = Mode::EnterDnsAddr {
                    buffer: "127.0.0.1:9535".to_string(),
                };
            }
        }
        KeyCode::Char('k') => {
            state.mode = Mode::KillSwitchMenu;
        }
        KeyCode::Char('d') => {
            state.mode = Mode::ConfirmDisable;
        }
        _ => {}
    }
    false
}

fn draw(frame: &mut Frame, state: &AppState) {
    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(LOG_TAIL_LINES as u16 + 2),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(frame, rows[0], state);
    draw_services_panel(frame, rows[1], state);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(rows[2]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(5)])
        .split(cols[0]);
    draw_bridge_panel(frame, left[0], state);
    draw_candidates_panel(frame, left[1], state);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(cols[1]);
    draw_isolation_panel(frame, right[0], state);
    draw_killswitch_panel(frame, right[1], state);

    draw_log_panel(frame, rows[3], state);
    draw_help_line(frame, rows[4], state);
    draw_status_line(frame, rows[5], state);
}

fn draw_header(frame: &mut Frame, area: Rect, state: &AppState) {
    let uptime = state.started_at.elapsed();
    let text = format!(
        "anonet — live status        uptime {:02}:{:02}:{:02}",
        uptime.as_secs() / 3600,
        (uptime.as_secs() / 60) % 60,
        uptime.as_secs() % 60
    );
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_services_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    let dns_line = match state.dns_shim_addr {
        Some(addr) => format!("DNS shim:  UP on {addr}  (n to stop)"),
        None => "DNS shim:  not running  (n to start)".to_string(),
    };
    let bridge_count = state.health.candidates.len();
    let bridges_line = if bridge_count == 0 {
        "Bridges:   none configured (running in direct mode, a to add one)".to_string()
    } else {
        format!("Bridges:   {bridge_count} configured — see the candidates table below")
    };
    let text = format!(
        "SOCKS5:    UP on {}   ({} connections total, {} active)\n{}\n{}",
        state.services.socks_addr,
        state.health.socks_connections_total,
        state.health.socks_connections_active,
        dns_line,
        bridges_line,
    );
    frame.render_widget(
        Paragraph::new(text).block(Block::default().title("Services").borders(Borders::ALL)),
        area,
    );
}

fn draw_bridge_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    let h = &state.health;
    let lines = vec![
        format!(
            "active bridge:       {}",
            h.active_bridge_line.as_deref().unwrap_or("(direct, no bridge)")
        ),
        format!("consecutive failures: {}", h.consecutive_failures),
        format!("total failovers:      {}", h.total_switches),
        format!("last check:           {}", format_system_time(h.last_check_at)),
        format!("last switch:          {}", format_system_time(h.last_switch_at)),
    ];

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(2)])
        .split(Block::default().title("Bridge / Circuit").borders(Borders::ALL).inner(area));

    frame.render_widget(
        Paragraph::new(lines.join("\n")).block(Block::default().title("Bridge / Circuit").borders(Borders::ALL)),
        area,
    );

    let sparkline_data: Vec<u64> = h.history.iter().map(|s| if s.success { s.latency_ms } else { 0 }).collect();
    frame.render_widget(
        Sparkline::default()
            .block(Block::default().title("latency ms (0 = failed check)"))
            .data(&sparkline_data)
            .style(Style::default().fg(Color::Cyan)),
        inner[1],
    );
}

fn draw_candidates_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    let rows: Vec<Row> = state
        .health
        .candidates
        .iter()
        .map(|c| {
            let active = state.health.active_bridge_index == Some(c.index);
            let status = match c.last_success {
                Some(true) => "ok",
                Some(false) => "FAIL",
                None => "-",
            };
            let latency = c.last_latency_ms.map(|ms| format!("{ms}ms")).unwrap_or_else(|| "-".to_string());
            let marker = if active { "*" } else { " " };
            Row::new(vec![
                Cell::from(format!("{marker}{}", c.index)),
                Cell::from(c.line.clone()),
                Cell::from(status),
                Cell::from(latency),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Percentage(60),
        Constraint::Length(6),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .header(Row::new(vec!["#", "bridge", "status", "latency"]).style(Style::default().fg(Color::Yellow)))
        .block(
            Block::default()
                .title(format!("Bridge candidates ({}, * = active)", state.health.candidates.len()))
                .borders(Borders::ALL),
        );
    frame.render_widget(table, area);
}

fn draw_isolation_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    let rows: Vec<Row> = state
        .isolation
        .iter()
        .map(|(identity, uses, age)| {
            Row::new(vec![
                Cell::from(identity.clone()),
                Cell::from(uses.to_string()),
                Cell::from(format!("{}s", age.as_secs())),
            ])
        })
        .collect();

    let widths = [Constraint::Percentage(50), Constraint::Percentage(20), Constraint::Percentage(30)];
    let table = Table::new(rows, widths)
        .header(Row::new(vec!["identity", "uses", "age"]).style(Style::default().fg(Color::Yellow)))
        .block(
            Block::default()
                .title(format!("Isolation buckets ({})", state.isolation.len()))
                .borders(Borders::ALL),
        );
    frame.render_widget(table, area);
}

fn draw_killswitch_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    let label = |v: Option<bool>| match v {
        Some(true) => "ENABLED",
        Some(false) => "disabled",
        None => "unknown (needs root)",
    };
    let text = format!(
        "scoped: {}    radical: {}",
        label(state.killswitches.scoped),
        label(state.killswitches.radical)
    );
    frame.render_widget(
        Paragraph::new(text).block(Block::default().title("Kill switches").borders(Borders::ALL)),
        area,
    );
}

fn draw_log_panel(frame: &mut Frame, area: Rect, state: &AppState) {
    frame.render_widget(
        Paragraph::new(state.log_tail.join("\n")).block(Block::default().title("Recent log").borders(Borders::ALL)),
        area,
    );
}

/// Always-visible, context-sensitive list of keys the user can press right
/// now — separate from the line below it, which holds one-off results.
fn draw_help_line(frame: &mut Frame, area: Rect, state: &AppState) {
    frame.render_widget(
        Paragraph::new(help_text(&state.mode)).style(Style::default().fg(Color::Yellow)),
        area,
    );
}

fn draw_status_line(frame: &mut Frame, area: Rect, state: &AppState) {
    let text = match &state.mode {
        Mode::AddBridge { buffer } => format!("add bridge> {buffer}\u{2588}"),
        Mode::EnterScopedUid { buffer } => format!("scoped kill switch, protect uid> {buffer}\u{2588}"),
        Mode::EnterDnsAddr { buffer } => format!("DNS shim bind address> {buffer}\u{2588}"),
        _ => state.status_line.clone(),
    };
    frame.render_widget(Paragraph::new(text), area);
}

fn format_system_time(t: Option<std::time::SystemTime>) -> String {
    match t {
        None => "never".to_string(),
        Some(t) => match t.elapsed() {
            Ok(elapsed) => format!("{}s ago", elapsed.as_secs()),
            Err(_) => "just now".to_string(),
        },
    }
}
