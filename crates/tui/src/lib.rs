//! Live status dashboard (`anonet run --tui`): bridge/circuit health with
//! a latency sparkline, the full bridge-candidate pool's last known
//! status, active isolation buckets, kill switch status, and a tail of
//! the log file — all read from the same `CoreHandle` and
//! `anonet-telemetry` channel the rest of the app uses, no separate IPC.
//!
//! The only action exposed is *disabling* a kill switch (`d`, then
//! `s`/`r`). Deliberately one-directional: turning a kill switch off is
//! always safe to offer from a dashboard, but turning the radical one on
//! is a disruptive, whole-machine action that deserves the explicit
//! `anonet killswitch enable` command, not a stray keypress. `c` forces
//! an immediate health check of the active bridge instead of waiting out
//! the rest of the check interval.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
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
use anonet_leakguard::KillSwitch;
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

struct AppState {
    started_at: Instant,
    health: HealthStatus,
    isolation: Vec<(String, u32, Duration)>,
    killswitches: KillSwitchView,
    status_line: String,
    pending_disable_prompt: bool,
    log_tail: Vec<String>,
}

/// Runs the dashboard until the user quits (`q`/Esc). Takes over the
/// terminal (raw mode + alternate screen) for the duration and always
/// restores it on the way out, including on error.
///
/// `check_now` lets the `c` key wake `anonet-bridges::BridgeMonitor`
/// early instead of waiting out the rest of its check interval.
/// `log_path` is tailed on every refresh tick for the log panel.
pub async fn run(
    core: Arc<CoreHandle>,
    mut health_rx: watch::Receiver<HealthStatus>,
    check_now: Arc<Notify>,
    log_path: PathBuf,
) -> Result<()> {
    enable_raw_mode()?;
    execute!(std::io::stdout(), EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut state = AppState {
        started_at: Instant::now(),
        health: health_rx.borrow().clone(),
        isolation: Vec::new(),
        killswitches: KillSwitchView::default(),
        status_line: "q: quit   c: check bridge now   d: disable a kill switch".to_string(),
        pending_disable_prompt: false,
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
            }
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        if handle_key(key.code, &mut state, &check_now).await {
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
async fn handle_key(code: KeyCode, state: &mut AppState, check_now: &Notify) -> bool {
    if state.pending_disable_prompt {
        match code {
            KeyCode::Char('s') => {
                state.pending_disable_prompt = false;
                state.status_line = match (KillSwitch::Scoped { protect_uid: 0 }).disable().await {
                    Ok(()) => "scoped kill switch disabled".to_string(),
                    Err(err) => format!("failed to disable scoped kill switch: {err}"),
                };
                refresh_killswitch_status(state).await;
            }
            KeyCode::Char('r') => {
                state.pending_disable_prompt = false;
                state.status_line = match (KillSwitch::Radical { anonet_uid: 0 }).disable().await {
                    Ok(()) => "radical kill switch disabled".to_string(),
                    Err(err) => format!("failed to disable radical kill switch: {err}"),
                };
                refresh_killswitch_status(state).await;
            }
            KeyCode::Esc => {
                state.pending_disable_prompt = false;
                state.status_line = "cancelled".to_string();
            }
            _ => {}
        }
        return false;
    }

    match code {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        KeyCode::Char('c') => {
            check_now.notify_one();
            state.status_line = "requested an immediate bridge health check".to_string();
        }
        KeyCode::Char('d') => {
            state.pending_disable_prompt = true;
            state.status_line = "disable which kill switch?  [s]coped   [r]adical   [Esc] cancel".to_string();
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
            Constraint::Min(10),
            Constraint::Length(LOG_TAIL_LINES as u16 + 2),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(frame, rows[0], state);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(rows[1]);

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

    draw_log_panel(frame, rows[2], state);
    draw_status_line(frame, rows[3], state);
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

fn draw_status_line(frame: &mut Frame, area: Rect, state: &AppState) {
    frame.render_widget(Paragraph::new(state.status_line.clone()), area);
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
