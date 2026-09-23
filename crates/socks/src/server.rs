//! Minimal hand-rolled SOCKS5 (RFC 1928/1929) front end, CONNECT-only.
//!
//! Milestone 2 scope: accept a connection, negotiate either no-auth or
//! username/password auth, parse the CONNECT request, forward the raw
//! destination (hostname preferred) into `AnonCore::connect_isolated`, and
//! splice bytes both ways. The SOCKS5 username (when the client
//! authenticates) is used purely as an *isolation key* — like Tor's own
//! `IsolateSOCKSAuth` — not as a real credential check: any username/password
//! is accepted, but distinct usernames get distinct circuits. Clients that
//! skip auth all share one "default" isolation bucket.
//! DNS-leak policy (rejecting raw-IP CONNECTs) is enforced here but decided
//! by `anonet-leakguard::LeakPolicy`. ACLs beyond that land in a later
//! milestone.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use anonet_core::CoreHandle;
use anonet_leakguard::{Destination, LeakPolicy};
use anonet_telemetry::Reporter;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const USERPASS_VERSION: u8 = 0x01;
const USERPASS_STATUS_OK: u8 = 0x00;
const DEFAULT_ISOLATION: &str = "default";
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CONN_NOT_ALLOWED: u8 = 0x02;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

pub struct ListenerConfig {
    pub bind: SocketAddr,
}

pub struct SocksServer {
    core: Arc<CoreHandle>,
    policy: LeakPolicy,
    telemetry: Reporter,
}

impl SocksServer {
    pub fn new(core: Arc<CoreHandle>, telemetry: Reporter) -> Self {
        Self::with_policy(core, LeakPolicy::strict(), telemetry)
    }

    pub fn with_policy(core: Arc<CoreHandle>, policy: LeakPolicy, telemetry: Reporter) -> Self {
        Self { core, policy, telemetry }
    }

    pub async fn run(&self, cfg: ListenerConfig) -> Result<()> {
        let listener = self.bind(cfg).await?;
        self.serve(listener).await
    }

    /// Binds the listener without serving yet. Split out so a caller (the
    /// dashboard) can fail loudly and immediately if the port is already
    /// taken — e.g. by an orphaned previous `anonet` instance — instead of
    /// finding out from a background task's error, well after having
    /// already rendered "SOCKS5: UP".
    pub async fn bind(&self, cfg: ListenerConfig) -> Result<TcpListener> {
        let listener = TcpListener::bind(cfg.bind)
            .await
            .with_context(|| format!("failed to bind SOCKS5 listener on {}", cfg.bind))?;
        info!(addr = %cfg.bind, "SOCKS5 listener up");
        Ok(listener)
    }

    pub async fn serve(&self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let core = Arc::clone(&self.core);
            let policy = self.policy;
            let telemetry = self.telemetry.clone();
            tokio::spawn(async move {
                telemetry.connection_opened();
                if let Err(err) = handle_conn(stream, core, policy).await {
                    debug!(%peer, error = %err, "SOCKS5 session ended with error");
                }
                telemetry.connection_closed();
            });
        }
    }
}

async fn handle_conn(mut client: TcpStream, core: Arc<CoreHandle>, policy: LeakPolicy) -> Result<()> {
    let identity = negotiate_method(&mut client).await?;
    let (dest, port) = read_connect_request(&mut client).await?;

    if let Err(violation) = policy.check(&dest) {
        warn!(%violation, "rejecting CONNECT request per DNS-leak policy");
        send_reply(&mut client, REP_CONN_NOT_ALLOWED).await.ok();
        return Err(violation.into());
    }

    let host_for_connect = match &dest {
        Destination::Host(h) => h.clone(),
        Destination::Ip(ip) => ip.to_string(),
    };

    let core = core.current().await;
    let upstream = match core
        .connect_isolated(&host_for_connect, port, &identity)
        .await
    {
        Ok(s) => s,
        Err(err) => {
            send_reply(&mut client, REP_GENERAL_FAILURE).await.ok();
            return Err(err);
        }
    };

    send_reply(&mut client, REP_SUCCESS).await?;
    splice(client, upstream).await
}

/// Negotiates the SOCKS5 auth method and returns the isolation identity to
/// use for this connection: the authenticated username, or `"default"` if
/// the client chose not to authenticate.
async fn negotiate_method(client: &mut TcpStream) -> Result<String> {
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    let [ver, nmethods] = hdr;
    if ver != SOCKS_VERSION {
        bail!("unsupported SOCKS version {ver}");
    }
    let mut methods = vec![0u8; nmethods as usize];
    client.read_exact(&mut methods).await?;

    if methods.contains(&METHOD_USERPASS) {
        client.write_all(&[SOCKS_VERSION, METHOD_USERPASS]).await?;
        read_userpass_identity(client).await
    } else if methods.contains(&METHOD_NO_AUTH) {
        client.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        Ok(DEFAULT_ISOLATION.to_string())
    } else {
        client
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        bail!("client offered no acceptable auth method");
    }
}

/// RFC 1929 username/password subnegotiation. The password is read (the
/// protocol requires it) but never checked — only the username is used, as
/// an isolation key rather than a credential.
async fn read_userpass_identity(client: &mut TcpStream) -> Result<String> {
    let mut ver = [0u8; 1];
    client.read_exact(&mut ver).await?;
    if ver[0] != USERPASS_VERSION {
        bail!("unsupported username/password subnegotiation version {}", ver[0]);
    }

    let mut ulen = [0u8; 1];
    client.read_exact(&mut ulen).await?;
    let mut uname = vec![0u8; ulen[0] as usize];
    client.read_exact(&mut uname).await?;

    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).await?;
    let mut passwd = vec![0u8; plen[0] as usize];
    client.read_exact(&mut passwd).await?;

    client
        .write_all(&[USERPASS_VERSION, USERPASS_STATUS_OK])
        .await?;

    let identity = String::from_utf8(uname).context("SOCKS5 username was not valid UTF-8")?;
    if identity.is_empty() {
        Ok(DEFAULT_ISOLATION.to_string())
    } else {
        Ok(identity)
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
