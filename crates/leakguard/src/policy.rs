//! DNS-leak enforcement policy: decides whether a SOCKS5 CONNECT request is
//! allowed to proceed, based on how the destination was specified.

use std::net::IpAddr;

/// A SOCKS5 CONNECT destination, exactly as the client specified it.
#[derive(Debug, Clone)]
pub enum Destination {
    Host(String),
    Ip(IpAddr),
}

#[derive(Debug, thiserror::Error)]
pub enum LeakViolation {
    #[error(
        "raw IP address {0} rejected by DNS-leak policy: the client resolved this hostname \
         itself instead of letting it travel down the Tor circuit, which would leak the lookup \
         to the local/system DNS resolver. Configure the client for remote (SOCKS5) DNS resolution."
    )]
    RawIpRejected(IpAddr),
}

/// Anti-DNS-leak policy for the SOCKS5 front end.
///
/// The only way a plain SOCKS5 CONNECT-by-IP request can exist is if
/// *something upstream of us* already resolved the hostname — almost always
/// the local system resolver, outside Tor. Rejecting those requests by
/// default is what actually prevents the leak; everything else (the DNS
/// shim, `AnonCore::resolve`) is a convenience for well-behaved clients,
/// not the enforcement point.
#[derive(Debug, Clone, Copy)]
pub struct LeakPolicy {
    allow_raw_ip: bool,
}

impl Default for LeakPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

impl LeakPolicy {
    /// Reject any CONNECT request that names a raw IP address.
    pub fn strict() -> Self {
        Self { allow_raw_ip: false }
    }

    /// Allow raw-IP CONNECTs through. Only meaningful for a deployment that
    /// has its own way of guaranteeing DNS never touches the local
    /// resolver (e.g. every client is forced through the DNS shim first).
    pub fn permissive() -> Self {
        Self { allow_raw_ip: true }
    }

    pub fn check(&self, dest: &Destination) -> Result<(), LeakViolation> {
        match dest {
            Destination::Ip(ip) if !self.allow_raw_ip => Err(LeakViolation::RawIpRejected(*ip)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn strict_policy_rejects_raw_ip() {
        let policy = LeakPolicy::strict();
        let dest = Destination::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(policy.check(&dest).is_err());
    }

    #[test]
    fn strict_policy_allows_hostname() {
        let policy = LeakPolicy::strict();
        let dest = Destination::Host("example.com".to_string());
        assert!(policy.check(&dest).is_ok());
    }

    #[test]
    fn permissive_policy_allows_raw_ip() {
        let policy = LeakPolicy::permissive();
        let dest = Destination::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(policy.check(&dest).is_ok());
    }
}
