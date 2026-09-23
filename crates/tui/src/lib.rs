//! Live status dashboard (`anonet run --tui`): bridge/circuit health,
//! active isolation buckets, and kill switch status, all read from the
//! same `CoreHandle` and `anonet-telemetry` channel the rest of the app
//! uses — no separate IPC, this runs embedded in the `anonet run` process.
//!
//! The only action exposed here is *disabling* a kill switch (`d`, then
//! `s`/`r`). Deliberately one-directional: turning a kill switch off is
//! always safe to offer from a dashboard, but turning the radical one on
//! is a disruptive, whole-machine action that deserves the explicit
//! `anonet killswitch enable` command, not a stray keypress. Both actions
//! (and even a `list`) need root; if `anonet run --tui` isn't running as
//! root, the kill switch panel shows "unknown (needs root)" rather than
//! failing outright.

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
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use tokio::sync::watch;

use anonet_core::CoreHandle;
use anonet_leakguard::KillSwitch;
use anonet_telemetry::HealthStatus;

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
}

/// Runs the dashboard until the user quits (`q`/Esc). Takes over the
/// terminal (raw mode + alternate screen) for the duration and always
/// restores it on the way out, including on error.
pub async fn run(core: Arc<CoreHandle>, mut health_rx: watch::Receiver<HealthStatus>) -> Result<()> {
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
        status_line: "q: quit   d: disable a kill switch".to_string(),
        pending_disable_prompt: false,
    };
    refresh_snapshot(&core, &mut state).await;
    refresh_killswitch_status(&mut state).await;

    let mut events = EventStream::new();
    let mut refresh_tick = tokio::time::interval(Duration::from_secs(2));

    loop {
        terminal.draw(|frame| draw(frame, &state))?;

        tokio::select! {
            changed = health_rx.changed() => {
                if changed.is_err() {
                    // Sender dropped (the run() task ended); nothing more will
                    // come, but keep the dashboard usable for inspection/quit.
                } else {
                    state.health = health_rx.borrow().clone();
                }
            }
            _ = refresh_tick.tick() => {
                refresh_snapshot(&core, &mut state).await;
                refresh_killswitch_status(&mut state).await;
            }
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        if handle_key(key.code, &mut state).await {
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

    let _ = state; // silence "unused after last write" style lints on some toolchains
    Ok(())
}

async fn refresh_snapshot(core: &CoreHandle, state: &mut AppState) {
    let c = core.current().await;
    state.isolation = c.isolation_snapshot();
    state.isolation.sort_by(|a, b| a.0.cmp(&b.0));
}

async fn refresh_killswitch_status(state: &mut AppState) {
    state.killswitches.scoped = KillSwitch::Scoped { protect_uid: 0 }.is_enabled().await.ok();
    state.killswitches.radical = KillSwitch::Radical { anonet_uid: 0 }.is_enabled().await.ok();
}

/// Returns `true` if the app should quit.
async fn handle_key(code: KeyCode, state: &mut AppState) -> bool {
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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(7),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(frame, chunks[0], state);
    draw_bridge_panel(frame, chunks[1], state);
    draw_isolation_panel(frame, chunks[2], state);
    draw_killswitch_panel(frame, chunks[3], state);
    draw_status_line(frame, chunks[4], state);
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
            "active bridge:      {}",
            h.active_bridge_line.as_deref().unwrap_or("(direct, no bridge)")
        ),
        format!("consecutive failures: {}", h.consecutive_failures),
        format!("total failovers:     {}", h.total_switches),
        format!("last check:          {}", format_system_time(h.last_check_at)),
        format!("last switch:         {}", format_system_time(h.last_switch_at)),
    ];
    frame.render_widget(
        Paragraph::new(lines.join("\n")).block(Block::default().title("Bridge / Circuit").borders(Borders::ALL)),
        area,
    );
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
