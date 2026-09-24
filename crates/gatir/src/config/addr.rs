use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};

/// A parent proxy endpoint: `host:port`, or `[ipv6]:port` for IPv6 literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentAddr {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid parent proxy address \"{input}\": {reason}")]
pub struct ParentAddrError {
    input: String,
    reason: &'static str,
}

impl ParentAddrError {
    fn new(input: &str, reason: &'static str) -> Self {
        Self {
            input: input.to_owned(),
            reason,
        }
    }
}

impl FromStr for ParentAddr {
    type Err = ParentAddrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let fail = |reason| ParentAddrError::new(input, reason);

        if input.contains('/') {
            return Err(fail("expected HOST:PORT without a scheme or path"));
        }

        let (host, port) = if let Some(rest) = input.strip_prefix('[') {
            let (host, after) = rest
                .split_once(']')
                .ok_or_else(|| fail("missing closing ']' in IPv6 literal"))?;
            host.parse::<Ipv6Addr>()
                .map_err(|_| fail("invalid IPv6 literal"))?;
            let port = after
                .strip_prefix(':')
                .ok_or_else(|| fail("expected ':PORT' after the IPv6 literal"))?;
            (host, port)
        } else {
            let (host, port) = input
                .rsplit_once(':')
                .ok_or_else(|| fail("expected HOST:PORT"))?;
            if host.contains(':') {
                return Err(fail("IPv6 literals must be written as [addr]:port"));
            }
            if host.is_empty() {
                return Err(fail("host is empty"));
            }
            if !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            {
                return Err(fail("host contains invalid characters"));
            }
            (host, port)
        };

        let port: u16 = port
            .parse()
            .map_err(|_| fail("port is not a number in 1-65535"))?;
        if port == 0 {
            return Err(fail("port must not be 0"));
        }

        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

impl fmt::Display for ParentAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl<'de> Deserialize<'de> for ParentAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent(host: &str, port: u16) -> ParentAddr {
        ParentAddr {
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn parses_valid_addresses() {
        let cases = [
            ("proxy.example.com:8080", parent("proxy.example.com", 8080)),
            ("proxy:3128", parent("proxy", 3128)),
            ("10.0.0.1:80", parent("10.0.0.1", 80)),
            ("my_proxy-1.corp:65535", parent("my_proxy-1.corp", 65535)),
            ("[::1]:8080", parent("::1", 8080)),
            ("[2001:db8::1]:3128", parent("2001:db8::1", 3128)),
        ];
        for (input, expected) in cases {
            assert_eq!(
                input.parse::<ParentAddr>().as_ref(),
                Ok(&expected),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_invalid_addresses() {
        let cases = [
            "",
            "proxy",
            ":8080",
            "proxy:",
            "proxy:0",
            "proxy:65536",
            "proxy:http",
            "http://proxy:8080",
            "proxy:8080/path",
            "pro xy:8080",
            "::1:8080",
            "[::1]",
            "[::1:8080",
            "[nope]:8080",
            "[::1]8080",
        ];
        for input in cases {
            assert!(
                input.parse::<ParentAddr>().is_err(),
                "should reject {input:?}"
            );
        }
    }

    #[test]
    fn display_round_trips() {
        for input in ["proxy.example.com:8080", "[::1]:8080"] {
            let addr: ParentAddr = input.parse().unwrap();
            assert_eq!(addr.to_string(), input);
        }
    }
}
