//! Access control for incoming client connections.
//!
//! Rules are evaluated in order and the first rule whose source contains the
//! client address decides. If no rule matches, the default action applies.
//! Sources are IP addresses, CIDR ranges (IPv4 and IPv6) or `*`. Host names are
//! deliberately not supported: resolving them at load time makes the rule set
//! depend on DNS.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Allow,
    Deny,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Which client addresses a rule applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Every address, IPv4 and IPv6.
    Any,
    Net(IpNet),
}

impl Source {
    /// `ip` must already be canonical (see [`IpAddr::to_canonical`]).
    fn contains(&self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Net(net) => net.contains(&ip),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "invalid access rule source \"{input}\": expected an IP address, a CIDR range such as \
     10.0.0.0/8, or \"*\" (host names are not supported)"
)]
pub struct SourceError {
    input: String,
}

impl FromStr for Source {
    type Err = SourceError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let text = input.trim();
        if text == "*" {
            return Ok(Self::Any);
        }
        if let Ok(ip) = text.parse::<IpAddr>() {
            return Ok(Self::Net(IpNet::from(ip)));
        }
        // Host bits are ignored: `10.1.2.3/8` means the whole 10.0.0.0/8.
        text.parse::<IpNet>()
            .map(|net| Self::Net(net.trunc()))
            .map_err(|_| SourceError {
                input: input.to_owned(),
            })
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Net(net) => net.fmt(f),
        }
    }
}

impl<'de> Deserialize<'de> for Source {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// One access rule. In TOML: `{ allow = "10.0.0.0/8" }` or `{ deny = "*" }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub action: Action,
    pub source: Source,
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Spec {
            Allow(Source),
            Deny(Source),
        }

        Ok(match Spec::deserialize(deserializer)? {
            Spec::Allow(source) => Self {
                action: Action::Allow,
                source,
            },
            Spec::Deny(source) => Self {
                action: Action::Deny,
                source,
            },
        })
    }
}

/// An ordered rule list plus the action taken when no rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Acl {
    rules: Vec<Rule>,
    default: Action,
}

impl Acl {
    pub fn new(rules: Vec<Rule>, default: Action) -> Self {
        Self { rules, default }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn default_action(&self) -> Action {
        self.default
    }

    /// Decides what to do with a connection from `client`.
    pub fn check(&self, client: IpAddr) -> Action {
        // A dual-stack listener reports IPv4 clients as IPv4-mapped IPv6
        // addresses; without this they would never match IPv4 rules.
        let client = client.to_canonical();
        self.rules
            .iter()
            .find(|rule| rule.source.contains(client))
            .map_or(self.default, |rule| rule.action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn rule(action: Action, source: &str) -> Rule {
        Rule {
            action,
            source: source.parse().unwrap(),
        }
    }

    fn allow(source: &str) -> Rule {
        rule(Action::Allow, source)
    }

    fn deny(source: &str) -> Rule {
        rule(Action::Deny, source)
    }

    #[test]
    fn the_default_applies_when_no_rule_matches() {
        assert_eq!(Acl::default().check(ip("10.0.0.1")), Action::Allow);
        assert_eq!(
            Acl::new(vec![], Action::Deny).check(ip("10.0.0.1")),
            Action::Deny
        );
        let acl = Acl::new(vec![allow("10.0.0.0/8")], Action::Deny);
        assert_eq!(acl.check(ip("11.0.0.1")), Action::Deny);
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let allow_first = Acl::new(vec![allow("127.0.0.1"), deny("*")], Action::Allow);
        assert_eq!(allow_first.check(ip("127.0.0.1")), Action::Allow);
        assert_eq!(allow_first.check(ip("10.0.0.1")), Action::Deny);

        let deny_first = Acl::new(vec![deny("*"), allow("127.0.0.1")], Action::Allow);
        assert_eq!(deny_first.check(ip("127.0.0.1")), Action::Deny);
    }

    #[test]
    fn cidr_ranges_match_only_their_members() {
        let acl = Acl::new(
            vec![allow("10.0.0.0/8"), allow("192.168.1.128/25")],
            Action::Deny,
        );
        for (client, expected) in [
            ("10.0.0.0", Action::Allow),
            ("10.255.255.255", Action::Allow),
            ("9.255.255.255", Action::Deny),
            ("11.0.0.0", Action::Deny),
            ("192.168.1.128", Action::Allow),
            ("192.168.1.255", Action::Allow),
            ("192.168.1.127", Action::Deny),
            ("192.168.2.128", Action::Deny),
        ] {
            assert_eq!(acl.check(ip(client)), expected, "{client}");
        }
    }

    #[test]
    fn host_bits_in_a_range_are_ignored() {
        let acl = Acl::new(vec![allow("10.9.9.9/8")], Action::Deny);
        assert_eq!(acl.check(ip("10.0.0.1")), Action::Allow);
        assert_eq!(acl.rules()[0].source.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn ipv6_clients_are_subject_to_the_rules() {
        // Regression: a rule set that ends with "deny everything" must also
        // stop IPv6 clients.
        let acl = Acl::new(
            vec![allow("::1"), allow("fd00::/8"), deny("*")],
            Action::Allow,
        );
        for (client, expected) in [
            ("::1", Action::Allow),
            ("fd12:3456::1", Action::Allow),
            ("fe80::1", Action::Deny),
            ("2001:db8::1", Action::Deny),
        ] {
            assert_eq!(acl.check(ip(client)), expected, "{client}");
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_clients_match_ipv4_rules() {
        let acl = Acl::new(vec![allow("10.0.0.0/8")], Action::Deny);
        assert_eq!(acl.check(ip("::ffff:10.1.2.3")), Action::Allow);
        assert_eq!(acl.check(ip("::ffff:11.1.2.3")), Action::Deny);
    }

    #[test]
    fn address_families_do_not_cross_match() {
        let v4_only = Acl::new(vec![allow("0.0.0.0/0")], Action::Deny);
        assert_eq!(v4_only.check(ip("192.0.2.1")), Action::Allow);
        assert_eq!(v4_only.check(ip("2001:db8::1")), Action::Deny);

        let v6_only = Acl::new(vec![allow("::/0")], Action::Deny);
        assert_eq!(v6_only.check(ip("2001:db8::1")), Action::Allow);
        assert_eq!(v6_only.check(ip("192.0.2.1")), Action::Deny);
    }

    #[test]
    fn star_matches_both_families() {
        let acl = Acl::new(vec![deny("*")], Action::Allow);
        assert_eq!(acl.check(ip("192.0.2.1")), Action::Deny);
        assert_eq!(acl.check(ip("2001:db8::1")), Action::Deny);
    }

    #[test]
    fn rejects_invalid_sources() {
        for input in [
            "",
            "10.0.0.0/33",
            "::/129",
            "10.0.0/8",
            "10.0.0.0/8/9",
            "300.0.0.1",
            "example.com",
            "*.example.com",
            "any",
        ] {
            assert!(input.parse::<Source>().is_err(), "should reject {input:?}");
        }
    }

    #[test]
    fn sources_display_in_canonical_form() {
        for (input, shown) in [
            ("*", "*"),
            (" 127.0.0.1 ", "127.0.0.1/32"),
            ("10.1.2.3/8", "10.0.0.0/8"),
            ("::1", "::1/128"),
        ] {
            assert_eq!(
                input.parse::<Source>().unwrap().to_string(),
                shown,
                "{input}"
            );
        }
    }

    /// Small deterministic generator, so the reference-model tests below need
    /// no extra dependency and are reproducible.
    fn pseudo_random(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *seed
    }

    #[test]
    fn ipv4_matching_agrees_with_a_bit_mask_model() {
        let mut seed = 1;
        for len in 0..=32u32 {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            for _ in 0..200 {
                let network = (pseudo_random(&mut seed) >> 16) as u32;
                let candidate = if pseudo_random(&mut seed).is_multiple_of(2) {
                    // inside the range
                    (network & mask) | ((pseudo_random(&mut seed) >> 16) as u32 & !mask)
                } else {
                    (pseudo_random(&mut seed) >> 16) as u32
                };
                let source: Source = format!("{}/{len}", std::net::Ipv4Addr::from(network))
                    .parse()
                    .unwrap();
                let expected = (candidate & mask) == (network & mask);
                let client = IpAddr::from(std::net::Ipv4Addr::from(candidate));
                assert_eq!(source.contains(client), expected, "{source} vs {client}");
            }
        }
    }

    #[test]
    fn ipv6_matching_agrees_with_a_bit_mask_model() {
        let mut seed = 2;
        let next128 = |seed: &mut u64| {
            (u128::from(pseudo_random(seed)) << 64) | u128::from(pseudo_random(seed))
        };
        for len in 0..=128u32 {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            for _ in 0..50 {
                let network = next128(&mut seed);
                let candidate = if pseudo_random(&mut seed).is_multiple_of(2) {
                    (network & mask) | (next128(&mut seed) & !mask)
                } else {
                    next128(&mut seed)
                };
                let source: Source = format!("{}/{len}", std::net::Ipv6Addr::from(network))
                    .parse()
                    .unwrap();
                let expected = (candidate & mask) == (network & mask);
                let client = IpAddr::from(std::net::Ipv6Addr::from(candidate));
                assert_eq!(source.contains(client), expected, "{source} vs {client}");
            }
        }
    }
}
