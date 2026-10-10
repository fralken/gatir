//! Destinations that bypass the parent proxy and are contacted directly.
//!
//! Each entry is either an IP address or CIDR range, matched against IP
//! literals, or a case-insensitive pattern (`*` any run of characters, `?` one
//! character) matched against the host name. Ports are never part of the match.

use std::net::IpAddr;

use ipnet::IpNet;
use wildmatch::WildMatch;

#[derive(Debug, thiserror::Error)]
pub enum NoProxyError {
    #[error("no_proxy entries must not be empty")]
    Empty,
    #[error("invalid no_proxy pattern \"{pattern}\": {reason}")]
    Pattern { pattern: String, reason: String },
}

#[derive(Debug, Clone, Default)]
pub struct NoProxy {
    entries: Vec<String>,
    nets: Vec<IpNet>,
    /// Lower-case, to be matched against a lower-cased host.
    patterns: Vec<WildMatch>,
}

impl NoProxy {
    pub fn new<I, S>(entries: I) -> Result<Self, NoProxyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut kept = Vec::new();
        let mut nets = Vec::new();
        let mut patterns = Vec::new();

        for entry in entries {
            let entry = entry.as_ref().trim();
            if entry.is_empty() {
                return Err(NoProxyError::Empty);
            }
            // An IPv6 address may be written in brackets, as in a URL.
            let unbracketed = entry
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
                .unwrap_or(entry);
            if let Ok(ip) = unbracketed.parse::<IpAddr>() {
                nets.push(IpNet::from(ip));
            } else if let Ok(net) = entry.parse::<IpNet>() {
                nets.push(net.trunc());
            } else if let Some(character) = entry.chars().find(|c| "[]{}".contains(*c)) {
                // A class or an alternative in a glob library: not here, where
                // only `*` and `?` mean anything, and a typo should be told.
                return Err(NoProxyError::Pattern {
                    pattern: entry.to_owned(),
                    reason: format!("{character:?} is not supported: only * and ? are wildcards"),
                });
            } else {
                patterns.push(WildMatch::new(&entry.to_ascii_lowercase()));
            }
            kept.push(entry.to_owned());
        }

        Ok(Self {
            entries: kept,
            nets,
            patterns,
        })
    }

    /// The entries as configured, trimmed.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Whether `host` (a name or IP literal, without port) must be contacted
    /// directly.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim();
        let host = host.strip_suffix('.').unwrap_or(host);
        let host = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() {
            return false;
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            let ip = ip.to_canonical();
            if self.nets.iter().any(|net| net.contains(&ip)) {
                return true;
            }
        }
        // Also applied to IP literals so that patterns such as `10.*` work.
        let host = host.to_ascii_lowercase();
        self.patterns.iter().any(|pattern| pattern.matches(&host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_proxy(entries: &[&str]) -> NoProxy {
        NoProxy::new(entries).unwrap()
    }

    #[test]
    fn an_empty_list_matches_nothing() {
        let none = NoProxy::default();
        assert!(!none.matches("localhost"));
        assert!(!none.matches("10.0.0.1"));
        assert!(none.entries().is_empty());
    }

    #[test]
    fn plain_names_match_exactly_and_ignore_case() {
        let list = no_proxy(&["localhost"]);
        for (host, expected) in [
            ("localhost", true),
            ("LOCALHOST", true),
            ("localhost.", true),
            ("notlocalhost", false),
            ("localhost.example.com", false),
            ("", false),
        ] {
            assert_eq!(list.matches(host), expected, "{host:?}");
        }
    }

    #[test]
    fn wildcards_match_across_labels() {
        let list = no_proxy(&["*.corp.example.com", "intranet-??.example.com"]);
        for (host, expected) in [
            ("a.corp.example.com", true),
            ("a.b.corp.example.com", true),
            ("A.CORP.EXAMPLE.COM", true),
            ("corp.example.com", false),
            ("example.com", false),
            ("intranet-01.example.com", true),
            ("intranet-1.example.com", false),
            ("intranet-001.example.com", false),
        ] {
            assert_eq!(list.matches(host), expected, "{host}");
        }
    }

    #[test]
    fn glob_patterns_also_apply_to_ip_literals() {
        let list = no_proxy(&["10.*", "192.168.?.*"]);
        for (host, expected) in [
            ("10.1.2.3", true),
            ("110.1.2.3", false),
            ("192.168.1.9", true),
            ("192.168.12.9", false),
        ] {
            assert_eq!(list.matches(host), expected, "{host}");
        }
    }

    #[test]
    fn cidr_entries_match_ip_literals() {
        let list = no_proxy(&["172.16.0.0/12", "192.0.2.7", "fe80::/10", "[::1]"]);
        for (host, expected) in [
            ("172.16.0.1", true),
            ("172.31.255.255", true),
            ("172.32.0.1", false),
            ("192.0.2.7", true),
            ("192.0.2.8", false),
            ("fe80::1", true),
            ("[fe80::1]", true),
            ("[::1]", true),
            ("::1", true),
            ("::2", false),
            ("2001:db8::1", false),
            // IPv4-mapped IPv6 is treated as the IPv4 address it wraps
            ("::ffff:172.16.0.1", true),
        ] {
            assert_eq!(list.matches(host), expected, "{host}");
        }
    }

    #[test]
    fn cidr_entries_do_not_match_host_names() {
        let list = no_proxy(&["10.0.0.0/8"]);
        assert!(!list.matches("10.example.com"));
    }

    #[test]
    fn entries_are_trimmed_and_kept_in_order() {
        let list = no_proxy(&[" localhost ", "*.example.com"]);
        assert_eq!(list.entries(), ["localhost", "*.example.com"]);
        assert!(list.matches("localhost"));
    }

    #[test]
    fn rejects_empty_and_malformed_entries() {
        assert!(matches!(NoProxy::new([""]), Err(NoProxyError::Empty)));
        assert!(matches!(NoProxy::new(["  "]), Err(NoProxyError::Empty)));
        for entry in ["[unclosed", "[ab].example.com", "{a,b}.example.com"] {
            let err = NoProxy::new(["ok.example.com", entry]).unwrap_err();
            assert!(err.to_string().contains(entry), "{err}");
        }
    }
}
