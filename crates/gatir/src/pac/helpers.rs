//! The functions a PAC script can call: the classic list from the Netscape
//! specification, and the IPv6 variants ("Ex") that Microsoft added.
//!
//! Host names are compared without regard to case, since that is how they
//! work. `shExpMatch` is a shell pattern and is case sensitive.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use ipnet::IpNet;

use super::resolver::Resolver;

pub fn dns_domain_is(host: &str, domain: &str) -> bool {
    let (host, domain) = (host.as_bytes(), domain.as_bytes());
    host.len() >= domain.len() && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain)
}

pub fn local_host_or_domain_is(host: &str, host_or_domain: &str) -> bool {
    if host.eq_ignore_ascii_case(host_or_domain) {
        return true;
    }
    // A bare host name matches the first label of the fully qualified name.
    !host.is_empty()
        && !host.contains('.')
        && host_or_domain.len() > host.len()
        && host_or_domain.as_bytes()[..host.len()].eq_ignore_ascii_case(host.as_bytes())
        && host_or_domain.as_bytes()[host.len()] == b'.'
}

pub fn is_plain_host_name(host: &str) -> bool {
    !host.contains('.')
}

pub fn dns_domain_levels(host: &str) -> usize {
    host.matches('.').count()
}

/// Whether `text` matches the shell pattern, in which `*` stands for any run
/// of characters and `?` for exactly one. Everything else is itself.
pub fn sh_exp_match(text: &str, pattern: &str) -> bool {
    let text: Vec<char> = text.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    let (mut t, mut p) = (0, 0);
    // Where the last `*` was, and how much of the text it has taken so far.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
            }
            Some('?') => {
                t += 1;
                p += 1;
            }
            Some(&c) if c == text[t] => {
                t += 1;
                p += 1;
            }
            _ => match star {
                // Let the last `*` take one more character and try again.
                Some((star_p, star_t)) => {
                    star = Some((star_p, star_t + 1));
                    p = star_p + 1;
                    t = star_t + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

fn first_ipv4(resolver: &dyn Resolver, host: &str) -> Option<Ipv4Addr> {
    resolver
        .resolve(host)
        .into_iter()
        .find_map(|address| match address {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
}

/// `isInNet(host, pattern, mask)`: whether the IPv4 address of `host` is in
/// the network `pattern` under `mask`. A name is resolved first.
pub fn is_in_net(resolver: &dyn Resolver, host: &str, pattern: &str, mask: &str) -> bool {
    let (Ok(pattern), Ok(mask)) = (
        pattern.trim().parse::<Ipv4Addr>(),
        mask.trim().parse::<Ipv4Addr>(),
    ) else {
        return false;
    };
    let Some(address) = first_ipv4(resolver, host) else {
        return false;
    };
    (u32::from(address) & u32::from(mask)) == (u32::from(pattern) & u32::from(mask))
}

/// `isInNetEx(host, prefix)`: the same for IPv4 and IPv6, with the network
/// written as `address/length`. Any address of the host may be in it.
pub fn is_in_net_ex(resolver: &dyn Resolver, host: &str, prefix: &str) -> bool {
    let Ok(network) = prefix.trim().parse::<IpNet>() else {
        return false;
    };
    resolver
        .resolve(host)
        .iter()
        .any(|address| network.contains(address))
}

/// `dnsResolve(host)`: the first IPv4 address, or `None` if there is none.
pub fn dns_resolve(resolver: &dyn Resolver, host: &str) -> Option<String> {
    first_ipv4(resolver, host).map(|address| address.to_string())
}

/// `dnsResolveEx(host)`: every address, IPv4 and IPv6, separated by semicolons.
pub fn dns_resolve_ex(resolver: &dyn Resolver, host: &str) -> String {
    join(&resolver.resolve(host))
}

pub fn is_resolvable(resolver: &dyn Resolver, host: &str) -> bool {
    first_ipv4(resolver, host).is_some()
}

pub fn is_resolvable_ex(resolver: &dyn Resolver, host: &str) -> bool {
    !resolver.resolve(host).is_empty()
}

/// The address this machine would use to reach the network. Connecting a UDP
/// socket sends nothing: it only makes the system pick the outgoing interface.
fn local_address(remote: &str, bind: &str) -> Option<IpAddr> {
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(remote).ok()?;
    socket.local_addr().ok().map(|address| address.ip())
}

/// `myIpAddress()`: the IPv4 address of this machine on its way out, or the
/// loopback address if it has no route.
pub fn my_ip_address() -> String {
    // 192.0.2.1 is reserved for documentation: nothing is sent to it.
    local_address("192.0.2.1:9", "0.0.0.0:0")
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .to_string()
}

/// `myIpAddressEx()`: the IPv4 and IPv6 addresses, separated by semicolons.
pub fn my_ip_address_ex() -> String {
    let addresses: Vec<IpAddr> = [
        local_address("192.0.2.1:9", "0.0.0.0:0"),
        local_address("[2001:db8::1]:9", "[::]:0"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if addresses.is_empty() {
        IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
    } else {
        join(&addresses)
    }
}

/// `sortIpAddressList(list)`: the semicolon-separated addresses with IPv6
/// first, then IPv4, each kept in the order given. Text that is not an
/// address is dropped.
pub fn sort_ip_address_list(list: &str) -> String {
    let mut addresses: Vec<IpAddr> = list
        .split(';')
        .filter_map(|part| part.trim().parse().ok())
        .collect();
    addresses.sort_by_key(IpAddr::is_ipv4);
    join(&addresses)
}

fn join(addresses: &[IpAddr]) -> String {
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    use super::*;

    /// A resolver with fixed answers.
    #[derive(Debug, Default)]
    struct Table(HashMap<&'static str, Vec<IpAddr>>);

    impl Table {
        fn with(mut self, host: &'static str, addresses: &[&str]) -> Self {
            self.0
                .insert(host, addresses.iter().map(|a| a.parse().unwrap()).collect());
            self
        }
    }

    impl Resolver for Table {
        fn resolve(&self, host: &str) -> Vec<IpAddr> {
            if let Ok(address) = host.parse::<IpAddr>() {
                return vec![address];
            }
            self.0.get(host).cloned().unwrap_or_default()
        }
    }

    #[test]
    fn dns_domain_is_compares_the_end_of_the_host() {
        assert!(dns_domain_is("www.netscape.com", ".netscape.com"));
        assert!(dns_domain_is("WWW.Netscape.COM", ".netscape.com"));
        assert!(!dns_domain_is("www", ".netscape.com"));
        assert!(!dns_domain_is("www.mcom.com", ".netscape.com"));
        assert!(dns_domain_is("anything", ""));
    }

    #[test]
    fn local_host_or_domain_is_accepts_the_bare_host_name() {
        assert!(local_host_or_domain_is(
            "www.netscape.com",
            "www.netscape.com"
        ));
        assert!(local_host_or_domain_is("www", "www.netscape.com"));
        assert!(!local_host_or_domain_is("www.mcom.com", "www.netscape.com"));
        assert!(!local_host_or_domain_is(
            "home.netscape.com",
            "www.netscape.com"
        ));
        assert!(!local_host_or_domain_is("ww", "www.netscape.com"));
        assert!(!local_host_or_domain_is("", "www.netscape.com"));
    }

    #[test]
    fn plain_host_names_and_domain_levels() {
        assert!(is_plain_host_name("intranet"));
        assert!(!is_plain_host_name("www.example.com"));
        assert_eq!(dns_domain_levels("www"), 0);
        assert_eq!(dns_domain_levels("www.netscape.com"), 2);
    }

    #[test]
    fn shell_patterns() {
        for (text, pattern, expected) in [
            ("www.example.com", "*.example.com", true),
            ("http://www.example.com/a/b?c=1", "*.example.com/*", true),
            ("http://www.example.org/", "*.example.com/*", false),
            ("abc", "a?c", true),
            ("ac", "a?c", false),
            ("abc", "a??c", false),
            ("", "*", true),
            ("", "", true),
            ("abc", "", false),
            ("abc", "abc*", true),
            ("abc", "*abc", true),
            ("a.c", "a.c", true),
            ("abc", "a.c", false),
            ("a(b)", "a(b)", true),
            ("[x]", "[x]", true),
            ("Example.COM", "*.com", false),
            ("h\u{e9}llo", "h?llo", true),
            ("xaxbxc", "*a*b*c", true),
            ("xaxbx", "*a*b*c", false),
        ] {
            assert_eq!(
                sh_exp_match(text, pattern),
                expected,
                "{text:?} ~ {pattern:?}"
            );
        }
    }

    #[test]
    fn a_pattern_full_of_stars_does_not_take_exponential_time() {
        let text = "a".repeat(5000);
        let started = Instant::now();
        assert!(!sh_exp_match(&text, "*a*a*a*a*a*a*a*a*a*b"));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn is_in_net_takes_an_address_or_a_name() {
        let dns = Table::default().with("www.example.com", &["198.95.249.79"]);
        assert!(is_in_net(
            &dns,
            "198.95.249.79",
            "198.95.249.79",
            "255.255.255.255"
        ));
        assert!(is_in_net(
            &dns,
            "198.95.249.79",
            "198.95.0.0",
            "255.255.0.0"
        ));
        assert!(!is_in_net(&dns, "198.96.1.1", "198.95.0.0", "255.255.0.0"));
        assert!(is_in_net(
            &dns,
            "www.example.com",
            "198.95.0.0",
            "255.255.0.0"
        ));
        assert!(!is_in_net(
            &dns,
            "unknown.example.com",
            "198.95.0.0",
            "255.255.0.0"
        ));
    }

    #[test]
    fn is_in_net_is_false_for_nonsense() {
        let dns = Table::default();
        assert!(!is_in_net(&dns, "10.0.0.1", "not-an-address", "255.0.0.0"));
        assert!(!is_in_net(&dns, "10.0.0.1", "10.0.0.0", "nope"));
        assert!(!is_in_net(&dns, "", "10.0.0.0", "255.0.0.0"));
        // An IPv6 address is not in an IPv4 network.
        assert!(!is_in_net(&dns, "::1", "0.0.0.0", "0.0.0.0"));
    }

    #[test]
    fn is_in_net_ex_handles_both_families() {
        let dns = Table::default().with("v6.example.com", &["2001:db8::5"]);
        assert!(is_in_net_ex(&dns, "10.1.2.3", "10.0.0.0/8"));
        assert!(!is_in_net_ex(&dns, "11.1.2.3", "10.0.0.0/8"));
        assert!(is_in_net_ex(&dns, "2001:db8::1", "2001:db8::/32"));
        assert!(!is_in_net_ex(&dns, "2001:db9::1", "2001:db8::/32"));
        assert!(is_in_net_ex(&dns, "v6.example.com", "2001:db8::/32"));
        // Different families never match, and a bad prefix is false.
        assert!(!is_in_net_ex(&dns, "10.1.2.3", "2001:db8::/32"));
        assert!(!is_in_net_ex(&dns, "10.1.2.3", "10.0.0.0/33"));
        assert!(!is_in_net_ex(&dns, "10.1.2.3", "garbage"));
    }

    #[test]
    fn dns_resolve_gives_the_first_ipv4_address() {
        let dns = Table::default()
            .with("dual.example.com", &["2001:db8::1", "1.2.3.4", "5.6.7.8"])
            .with("v6only.example.com", &["2001:db8::1"]);
        assert_eq!(
            dns_resolve(&dns, "dual.example.com").as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(dns_resolve(&dns, "v6only.example.com"), None);
        assert_eq!(dns_resolve(&dns, "unknown.example.com"), None);
        assert_eq!(dns_resolve(&dns, "9.9.9.9").as_deref(), Some("9.9.9.9"));
        assert!(is_resolvable(&dns, "dual.example.com"));
        assert!(!is_resolvable(&dns, "v6only.example.com"));
    }

    #[test]
    fn the_ex_variants_keep_every_address() {
        let dns = Table::default().with("dual.example.com", &["1.2.3.4", "2001:db8::1"]);
        assert_eq!(
            dns_resolve_ex(&dns, "dual.example.com"),
            "1.2.3.4;2001:db8::1"
        );
        assert_eq!(dns_resolve_ex(&dns, "unknown.example.com"), "");
        assert!(is_resolvable_ex(&dns, "dual.example.com"));
        assert!(!is_resolvable_ex(&dns, "unknown.example.com"));
    }

    #[test]
    fn sorting_puts_ipv6_first_and_drops_junk() {
        assert_eq!(
            sort_ip_address_list("10.0.0.1; 2001:db8::2;junk;192.168.0.1;2001:db8::1"),
            "2001:db8::2;2001:db8::1;10.0.0.1;192.168.0.1"
        );
        assert_eq!(sort_ip_address_list(""), "");
    }

    #[test]
    fn my_ip_address_is_an_address() {
        assert!(my_ip_address().parse::<Ipv4Addr>().is_ok());
        let ex = my_ip_address_ex();
        assert!(!ex.is_empty());
        assert!(
            ex.split(';').all(|part| part.parse::<IpAddr>().is_ok()),
            "{ex}"
        );
    }
}
