//! Minimal hand-rolled Tor ControlPort client (the same "small, well-
//! understood text protocol, worth hand-rolling for full control" choice
//! made for SOCKS5 and DNS elsewhere in this codebase). We only need three
//! things from it: cookie auth, subscribing to `STREAM` events, and
//! parsing those events — not a general control-protocol library.

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use anonet_telemetry::{Reporter, StreamEvent};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Connects to `control_port`, authenticates with the cookie at
/// `cookie_path`, subscribes to `STREAM` events, and forwards each one into
/// `telemetry` until the connection drops (tor exits or the socket
/// closes). Meant to be spawned as a background task; logs and returns on
/// failure rather than panicking, since losing the event feed shouldn't
/// take down the rest of anonet.
pub async fn watch_streams(control_port: u16, cookie_path: &Path, telemetry: Arc<Reporter>) -> Result<()> {
    let cookie = tokio::fs::read(cookie_path)
        .await
        .with_context(|| format!("failed to read control auth cookie at {}", cookie_path.display()))?;
    let cookie_hex = cookie.iter().map(|b| format!("{b:02X}")).collect::<String>();

    let stream = TcpStream::connect(("127.0.0.1", control_port))
        .await
        .context("failed to connect to tor ControlPort")?;
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    write_half
        .write_all(format!("AUTHENTICATE {cookie_hex}\r\n").as_bytes())
        .await?;
    expect_ok(&mut lines).await.context("ControlPort AUTHENTICATE failed")?;

    write_half.write_all(b"SETEVENTS STREAM\r\n").await?;
    expect_ok(&mut lines).await.context("ControlPort SETEVENTS failed")?;

    tracing::info!("subscribed to tor ControlPort STREAM events");

    while let Some(line) = lines.next_line().await? {
        if let Some(event) = parse_stream_event(&line) {
            telemetry.update(|s| s.push_stream_event(event));
        }
    }

    bail!("ControlPort connection closed")
}

async fn expect_ok<R: tokio::io::AsyncBufRead + Unpin>(lines: &mut tokio::io::Lines<R>) -> Result<()> {
    let line = lines.next_line().await?.context("ControlPort closed before replying")?;
    if line.starts_with("250") {
        Ok(())
    } else {
        bail!("unexpected ControlPort reply: {line}")
    }
}

/// Parses a `650 STREAM StreamID Status CircID Target ...` control-spec
/// event line. Returns `None` for anything else (other event types,
/// malformed lines) — we only care about STREAM here.
fn parse_stream_event(line: &str) -> Option<StreamEvent> {
    let rest = line.strip_prefix("650 STREAM ")?;
    let mut parts = rest.split_whitespace();
    let _stream_id = parts.next()?;
    let status = parts.next()?.to_string();
    let _circ_id = parts.next()?;
    let target = parts.next()?.to_string();

    Some(StreamEvent {
        at: SystemTime::now(),
        status,
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_stream_succeeded_event() {
        let line = "650 STREAM 7 SUCCEEDED 4 example.com:443";
        let event = parse_stream_event(line).unwrap();
        assert_eq!(event.status, "SUCCEEDED");
        assert_eq!(event.target, "example.com:443");
    }

    #[test]
    fn ignores_non_stream_lines() {
        assert!(parse_stream_event("650 CIRC 4 BUILT").is_none());
        assert!(parse_stream_event("250 OK").is_none());
    }
}
