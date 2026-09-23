//! Minimal hand-rolled SOCKS5 (RFC 1928) front end, CONNECT-only, no-auth.
//!
//! Milestone 1 scope: accept a connection, parse the CONNECT request, forward
//! the raw destination (hostname preferred) into `AnonCore::connect`, and
//! splice bytes both ways. Auth-based isolation keys, IP-request rejection
//! (DNS-leak policy) and ACLs are added in later milestones.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use anonet_core::AnonCore;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

pub struct ListenerConfig {
    pub bind: SocketAddr,
}

pub struct SocksServer {
    core: Arc<AnonCore>,
}

enum Destination {
    Host(String),
    Ip(std::net::IpAddr),
}

impl SocksServer {
    pub fn new(core: Arc<AnonCore>) -> Self {
        Self { core }
    }

    pub async fn run(&self, cfg: ListenerConfig) -> Result<()> {
        let listener = TcpListener::bind(cfg.bind)
            .await
            .with_context(|| format!("failed to bind SOCKS5 listener on {}", cfg.bind))?;
        info!(addr = %cfg.bind, "SOCKS5 listener up");

        loop {
            let (stream, peer) = listener.accept().await?;
            let core = Arc::clone(&self.core);
            tokio::spawn(async move {
                if let Err(err) = handle_conn(stream, core).await {
                    debug!(%peer, error = %err, "SOCKS5 session ended with error");
                }
            });
        }
    }
}

async fn handle_conn(mut client: TcpStream, core: Arc<AnonCore>) -> Result<()> {
    negotiate_method(&mut client).await?;
    let (dest, port) = read_connect_request(&mut client).await?;

    let host_for_connect = match &dest {
        Destination::Host(h) => h.clone(),
        Destination::Ip(ip) => {
            warn!(%ip, "CONNECT request used a raw IP address; DNS-leak enforcement lands in milestone 4");
            ip.to_string()
        }
    };

    let upstream = match core.connect(&host_for_connect, port).await {
        Ok(s) => s,
        Err(err) => {
            send_reply(&mut client, REP_GENERAL_FAILURE).await.ok();
            return Err(err);
        }
    };

    send_reply(&mut client, REP_SUCCESS).await?;
    splice(client, upstream).await
}

async fn negotiate_method(client: &mut TcpStream) -> Result<()> {
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    let [ver, nmethods] = hdr;
    if ver != SOCKS_VERSION {
        bail!("unsupported SOCKS version {ver}");
    }
    let mut methods = vec![0u8; nmethods as usize];
    client.read_exact(&mut methods).await?;

    if methods.contains(&METHOD_NO_AUTH) {
        client.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        Ok(())
    } else {
        client
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        bail!("client offered no acceptable auth method");
    }
}

async fn read_connect_request(client: &mut TcpStream) -> Result<(Destination, u16)> {
    let mut hdr = [0u8; 4];
    client.read_exact(&mut hdr).await?;
    let [ver, cmd, _rsv, atyp] = hdr;
    if ver != SOCKS_VERSION {
        bail!("unsupported SOCKS version {ver} in request");
    }
    if cmd != CMD_CONNECT {
        send_reply(client, REP_CMD_NOT_SUPPORTED).await.ok();
        bail!("only CONNECT is supported (got cmd {cmd})");
    }

    let dest = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await?;
            Destination::Ip(Ipv4Addr::from(buf).into())
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            client.read_exact(&mut buf).await?;
            Destination::Ip(Ipv6Addr::from(buf).into())
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let mut name = vec![0u8; len_buf[0] as usize];
            client.read_exact(&mut name).await?;
            let host = String::from_utf8(name).context("domain name was not valid UTF-8")?;
            Destination::Host(host)
        }
        other => {
            send_reply(client, REP_ATYP_NOT_SUPPORTED).await.ok();
            bail!("unsupported address type {other}");
        }
    };

    let mut port_buf = [0u8; 2];
    client.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok((dest, port))
}

async fn send_reply(client: &mut TcpStream, rep: u8) -> Result<()> {
    // BND.ADDR/BND.PORT are unused (Tor circuits don't expose a stable local
    // bind address), so we report 0.0.0.0:0 as most SOCKS5 clients ignore it
    // for CONNECT beyond checking the reply header.
    let reply = [
        SOCKS_VERSION,
        rep,
        0x00,
        ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    client.write_all(&reply).await?;
    Ok(())
}

async fn splice(client: TcpStream, upstream: arti_client::DataStream) -> Result<()> {
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let client_to_tor = async {
        tokio::io::copy(&mut cr, &mut uw).await?;
        uw.shutdown().await
    };
    let tor_to_client = async {
        tokio::io::copy(&mut ur, &mut cw).await?;
        cw.shutdown().await
    };

    tokio::try_join!(client_to_tor, tor_to_client)?;
    Ok(())
}
