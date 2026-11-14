//! Static tunnels: a local port whose every connection is carried to one fixed
//! destination, through the parent proxy the configuration chooses.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use serde::Deserialize;

use super::addr::{HostPort, HostPortError};

/// Where a tunnel listens when no address is given: the loopback only, so that
/// a forwarded port is not offered to the network by accident.
const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    pub listen: SocketAddr,
    pub target: HostPort,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TunnelError {
    #[error("invalid tunnel \"{input}\": {reason}")]
    Syntax { input: String, reason: &'static str },
    #[error("invalid tunnel destination: {0}")]
    Target(#[from] HostPortError),
}

/// The form used in the configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawTunnel {
    listen: SocketAddr,
    target: HostPort,
}

impl From<RawTunnel> for Tunnel {
    fn from(raw: RawTunnel) -> Self {
        Self {
            listen: raw.listen,
            target: raw.target,
        }
    }
}

/// The OpenSSH form of a local forward, `[BIND:]PORT:HOST:HOSTPORT`, with IPv6
/// addresses in square brackets. `BIND` is an address, `*` for every IPv4
/// interface, or `localhost`; without it the tunnel listens on the loopback.
impl FromStr for Tunnel {
    type Err = TunnelError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let fail = |reason| TunnelError::Syntax {
            input: input.to_owned(),
            reason,
        };
        let parts =
            split_outside_brackets(input).ok_or_else(|| fail("a '[' has no closing ']'"))?;
        let (bind, [port, host, target_port]) = match parts.as_slice() {
            [port, host, target_port] => (None, [*port, *host, *target_port]),
            [bind, port, host, target_port] => (Some(*bind), [*port, *host, *target_port]),
            _ => return Err(fail("expected [BIND:]PORT:HOST:HOSTPORT")),
        };

        let bind = match bind {
            None => DEFAULT_BIND,
            Some("*") => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Some("localhost") => DEFAULT_BIND,
            Some(text) => text
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse()
                .map_err(|_| fail("the address to listen on is not an IP address"))?,
        };
        let port = match port.parse::<u16>() {
            Ok(port) if port != 0 => port,
            _ => return Err(fail("the port to listen on is not a number in 1-65535")),
        };
        let target: HostPort = format!("{host}:{target_port}").parse()?;

        Ok(Self {
            listen: SocketAddr::new(bind, port),
            target,
        })
    }
}

/// Splits at every `:` that is not inside square brackets. `None` if the
/// brackets do not close.
fn split_outside_brackets(text: &str) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (at, byte) in text.bytes().enumerate() {
        match byte {
            b'[' => depth += 1,
            b']' => depth = depth.checked_sub(1)?,
            b':' if depth == 0 => {
                parts.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    parts.push(&text[start..]);
    Some(parts)
}

impl fmt::Display for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.listen, self.target)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::config::testing::{error_text, load};
    use crate::config::*;

    fn tunnel(listen: &str, host: &str, port: u16) -> Tunnel {
        Tunnel {
            listen: listen.parse().unwrap(),
            target: HostPort {
                host: host.to_owned(),
                port,
            },
        }
    }

    #[test]
    fn the_openssh_forms_are_understood() {
        for (text, expected) in [
            (
                "2222:git.example.com:22",
                tunnel("127.0.0.1:2222", "git.example.com", 22),
            ),
            ("127.0.0.1:2222:git:22", tunnel("127.0.0.1:2222", "git", 22)),
            ("0.0.0.0:2222:git:22", tunnel("0.0.0.0:2222", "git", 22)),
            ("*:2222:git:22", tunnel("0.0.0.0:2222", "git", 22)),
            ("localhost:2222:git:22", tunnel("127.0.0.1:2222", "git", 22)),
            ("[::1]:2222:git:22", tunnel("[::1]:2222", "git", 22)),
            (
                "2222:[2001:db8::1]:22",
                tunnel("127.0.0.1:2222", "2001:db8::1", 22),
            ),
            (
                "[::1]:2222:[2001:db8::1]:22",
                tunnel("[::1]:2222", "2001:db8::1", 22),
            ),
            (
                "10.1.2.3:2222:10.9.9.9:65535",
                tunnel("10.1.2.3:2222", "10.9.9.9", 65535),
            ),
        ] {
            assert_eq!(text.parse::<Tunnel>().as_ref(), Ok(&expected), "{text}");
        }
    }

    #[test]
    fn what_is_not_a_tunnel_is_refused() {
        for text in [
            "",
            "2222",
            "2222:git",
            "a:b:c:d:e",
            "2222:git:0",
            "0:git:22",
            "70000:git:22",
            "2222::22",
            "2222:g it:22",
            "2222:git:ssh",
            "not-an-address:2222:git:22",
            ":2222:git:22",
            "[::1:2222:git:22",
            "::1]:2222:git:22",
            "2222:http://git:22",
        ] {
            assert!(text.parse::<Tunnel>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn a_tunnel_reads_as_where_it_leads() {
        let tunnel: Tunnel = "127.0.0.1:2222:git.example.com:22".parse().unwrap();
        assert_eq!(tunnel.to_string(), "127.0.0.1:2222 -> git.example.com:22");
        let tunnel: Tunnel = "[::1]:2222:[2001:db8::1]:22".parse().unwrap();
        assert_eq!(tunnel.to_string(), "[::1]:2222 -> [2001:db8::1]:22");
    }

    #[test]
    fn tunnels_are_listed_as_tables() {
        let config = load(
            "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"git.example.com:22\"\n\
             [[tunnels]]\nlisten = \"[::1]:8443\"\ntarget = \"[2001:db8::1]:443\"",
        )
        .unwrap();
        let shown: Vec<String> = config.tunnels.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                "127.0.0.1:2222 -> git.example.com:22",
                "[::1]:8443 -> [2001:db8::1]:443"
            ]
        );
        assert!(load("").unwrap().tunnels.is_empty());
        assert!(
            config
                .summary()
                .contains("tunnels:     127.0.0.1:2222 -> git.example.com:22, ")
        );
        assert!(load("").unwrap().summary().contains("tunnels:     none"));
    }

    #[test]
    fn rejects_tunnels_that_make_no_sense() {
        for (toml, expected) in [
            ("[[tunnels]]\nlisten = \"127.0.0.1:2222\"", "missing field"),
            ("[[tunnels]]\ntarget = \"git:22\"", "missing field"),
            (
                "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"git\"",
                "invalid address",
            ),
            (
                "[[tunnels]]\nlisten = \"2222\"\ntarget = \"git:22\"",
                "invalid socket address",
            ),
            (
                "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"git:22\"\nsecret = 1",
                "unknown field",
            ),
            (
                "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"a:22\"\n\
                 [[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"b:22\"",
                "127.0.0.1:2222 is used by more than one listener",
            ),
            (
                "listen = [\"127.0.0.1:3128\"]\n[[tunnels]]\nlisten = \"127.0.0.1:3128\"\ntarget = \"a:22\"",
                "127.0.0.1:3128 is used by more than one listener",
            ),
        ] {
            let text = error_text(toml);
            assert!(text.contains(expected), "{toml:?} -> {text}");
        }
    }

    #[test]
    fn tunnels_on_the_command_line_replace_those_of_the_file() {
        let file = "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"file.example.com:22\"";
        let config = Config::from_toml_str(
            file,
            Overrides {
                tunnels: vec!["3333:cli.example.com:22".parse().unwrap()],
                ..Overrides::default()
            },
        )
        .unwrap();
        assert_eq!(config.tunnels.len(), 1);
        assert_eq!(config.tunnels[0].target.host, "cli.example.com");
        // Without any on the command line, the file's stay.
        let config = Config::from_toml_str(file, Overrides::default()).unwrap();
        assert_eq!(config.tunnels[0].target.host, "file.example.com");
    }
}
