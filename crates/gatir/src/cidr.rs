//! IP addresses and ranges as rules write them, shared by the access rules and
//! `no_proxy`.

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net};

/// An address or a CIDR range. A single address is a range of one, host bits
/// are ignored (`10.1.2.3/8` is 10.0.0.0/8), and an IPv4-mapped range
/// (`::ffff:10.0.0.0/104`) is the IPv4 range it stands for (`10.0.0.0/8`):
/// addresses are compared in their canonical form, in which a mapped address
/// is IPv4, so the mapped range would never match.
pub(crate) fn parse(text: &str) -> Option<IpNet> {
    let net = match text.parse::<IpAddr>() {
        Ok(ip) => IpNet::from(ip),
        Err(_) => text.parse::<IpNet>().ok()?.trunc(),
    };
    if let IpNet::V6(v6) = net
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.addr().to_ipv4_mapped()
    {
        return Ipv4Net::new(v4, v6.prefix_len() - 96).ok().map(IpNet::V4);
    }
    Some(net)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        text.parse().unwrap()
    }

    #[test]
    fn an_address_is_a_range_of_one() {
        assert_eq!(parse("10.1.2.3"), Some(net("10.1.2.3/32")));
        assert_eq!(parse("::1"), Some(net("::1/128")));
    }

    #[test]
    fn host_bits_are_ignored() {
        assert_eq!(parse("10.1.2.3/8"), Some(net("10.0.0.0/8")));
        assert_eq!(parse("fd00::1/16"), Some(net("fd00::/16")));
    }

    #[test]
    fn an_ipv4_mapped_range_is_read_as_ipv4() {
        assert_eq!(parse("::ffff:10.0.0.0/104"), Some(net("10.0.0.0/8")));
        assert_eq!(parse("::ffff:127.0.0.1"), Some(net("127.0.0.1/32")));
        // Wider than the mapped block: it covers more than IPv4 addresses.
        assert_eq!(parse("::ffff:0:0/80"), Some(net("::/80")));
    }

    #[test]
    fn anything_else_is_not_a_range() {
        for text in ["", "example.com", "10.0.0.0/33", "10.0.0.0/", "*"] {
            assert_eq!(parse(text), None, "{text}");
        }
    }
}
