mod dns_shim;
mod policy;

pub use dns_shim::DnsShim;
pub use policy::{Destination, LeakPolicy, LeakViolation};
