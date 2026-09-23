//! Minimal hand-rolled DNS-over-UDP server (RFC 1035 subset: one question,
//! A/AAAA only) that resolves every query via `AnonCore::resolve`, i.e.
//! through the Tor exit relay. For apps that insist on resolving names
//! themselves (instead of handing hostnames to the SOCKS5 proxy), pointing
//! their resolver at this server keeps that resolution off the system DNS
//! path too.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use anonet_core::CoreHandle;

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;

const RCODE_NOERROR: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;

const ANSWER_TTL_SECS: u32 = 60;

pub struct DnsShim {
    core: Arc<CoreHandle>,
}

struct ParsedQuery {
    id: u16,
    /// The question's raw bytes (name + qtype + qclass) as they appeared in
    /// the request, so the response can echo them back verbatim.
    question_raw: Vec<u8>,
    qname: String,
    qtype: u16,
}

impl DnsShim {
    pub fn new(core: Arc<CoreHandle>) -> Self {
        Self { core }
    }

    pub async fn run(&self, bind: SocketAddr) -> Result<()> {
        let socket = Arc::new(
            UdpSocket::bind(bind)
                .await
                .with_context(|| format!("failed to bind DNS shim on {bind}"))?,
        );
        info!(addr = %bind, "DNS shim listening (resolves via Tor, never touches the system resolver)");

        let mut buf = [0u8; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await?;
            let request = buf[..len].to_vec();
            let core = Arc::clone(&self.core);
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                if let Err(err) = handle_query(&core, &socket, &request, peer).await {
                    debug!(%peer, error = %err, "DNS shim query failed");
                }
            });
        }
    }
}

async fn handle_query(
    core: &CoreHandle,
    socket: &UdpSocket,
    request: &[u8],
    peer: SocketAddr,
) -> Result<()> {
    let query = match parse_query(request) {
        Ok(q) => q,
        Err(err) => {
            warn!(%peer, error = %err, "malformed DNS query, dropping");
            return Ok(());
        }
    };

    if query.qtype != QTYPE_A && query.qtype != QTYPE_AAAA {
        let response = build_response(query.id, &query.question_raw, query.qtype, RCODE_NOTIMP, &[]);
        socket.send_to(&response, peer).await?;
        return Ok(());
    }

    let core = core.current().await;
    let response = match core.resolve(&query.qname).await {
        Ok(ips) => {
            let wanted_v6 = query.qtype == QTYPE_AAAA;
            let filtered: Vec<IpAddr> = ips
                .into_iter()
                .filter(|ip| ip.is_ipv6() == wanted_v6)
                .collect();
            if filtered.is_empty() {
                build_response(query.id, &query.question_raw, query.qtype, RCODE_NXDOMAIN, &[])
            } else {
                build_response(query.id, &query.question_raw, query.qtype, RCODE_NOERROR, &filtered)
            }
        }
        Err(err) => {
            debug!(name = %query.qname, error = %err, "resolution via Tor failed");
            build_response(query.id, &query.question_raw, query.qtype, RCODE_SERVFAIL, &[])
        }
    };

    socket.send_to(&response, peer).await?;
    Ok(())
}

/// Parses a DNS message down to its single question, assuming an
/// uncompressed QNAME (true for essentially every stub-resolver query).
fn parse_query(buf: &[u8]) -> Result<ParsedQuery> {
    if buf.len() < 12 {
        bail!("message shorter than a DNS header");
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        bail!("query has no questions");
    }

    let question_start = 12;
    let mut pos = question_start;
    let mut labels = Vec::new();
    loop {
        let len = *buf.get(pos).context("truncated qname")? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            bail!("compressed QNAME in a query is not supported");
        }
        pos += 1;
        let label = buf
            .get(pos..pos + len)
            .context("truncated qname label")?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
    }
    let qname = labels.join(".");

    let qtype_qclass = buf.get(pos..pos + 4).context("truncated qtype/qclass")?;
    let qtype = u16::from_be_bytes([qtype_qclass[0], qtype_qclass[1]]);
    let qclass = u16::from_be_bytes([qtype_qclass[2], qtype_qclass[3]]);
    if qclass != QCLASS_IN {
        bail!("unsupported query class {qclass}");
    }
    let question_end = pos + 4;

    Ok(ParsedQuery {
        id,
        question_raw: buf[question_start..question_end].to_vec(),
        qname,
        qtype,
    })
}

/// Builds a DNS response for a single question, answering with `ips` (all
/// assumed to match `qtype`'s address family).
fn build_response(id: u16, question_raw: &[u8], qtype: u16, rcode: u8, ips: &[IpAddr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);

    out.extend_from_slice(&id.to_be_bytes());
    // QR=1 (response), Opcode=0000, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=rcode.
    let flags: u16 = 0x8180 | u16::from(rcode & 0x0F);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(ips.len() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    out.extend_from_slice(question_raw);

    for ip in ips {
        out.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to the question's QNAME
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&QCLASS_IN.to_be_bytes());
        out.extend_from_slice(&ANSWER_TTL_SECS.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Hand-built query for "example.com" A record, ID 0x1234, RD set.
    fn sample_a_query(id: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        for label in ["example", "com"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root label
        buf.extend_from_slice(&QTYPE_A.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
        buf
    }

    #[test]
    fn parses_qname_and_qtype() {
        let query = parse_query(&sample_a_query(0x1234)).unwrap();
        assert_eq!(query.id, 0x1234);
        assert_eq!(query.qname, "example.com");
        assert_eq!(query.qtype, QTYPE_A);
    }

    #[test]
    fn rejects_compressed_qname() {
        let mut buf = sample_a_query(1);
        buf[12] = 0xC0; // turn the first label length byte into a compression pointer
        assert!(parse_query(&buf).is_err());
    }

    #[test]
    fn response_roundtrips_id_and_answer() {
        let query = parse_query(&sample_a_query(0xBEEF)).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let response = build_response(query.id, &query.question_raw, query.qtype, RCODE_NOERROR, &[ip]);

        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0xBEEF);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);
        // Last 4 bytes of a single-A-record response are the IPv4 RDATA.
        assert_eq!(&response[response.len() - 4..], &[93, 184, 216, 34]);
    }

    #[test]
    fn nxdomain_response_has_zero_answers_and_rcode_3() {
        let query = parse_query(&sample_a_query(1)).unwrap();
        let response = build_response(query.id, &query.question_raw, query.qtype, RCODE_NXDOMAIN, &[]);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 0);
        assert_eq!(response[3] & 0x0F, RCODE_NXDOMAIN);
    }
}
