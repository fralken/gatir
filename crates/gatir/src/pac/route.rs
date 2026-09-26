//! The value `FindProxyForURL` returns: a list of ways to reach a destination.

use std::fmt;

/// The address of a proxy named in a PAC result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAddr {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for ProxyAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// One entry of a PAC result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Connect to the destination itself.
    Direct,
    /// An HTTP proxy: `PROXY` or `HTTP`.
    Proxy(ProxyAddr),
    /// An HTTP proxy reached over TLS: `HTTPS`.
    Https(ProxyAddr),
    /// A SOCKS proxy of unspecified version: `SOCKS`.
    Socks(ProxyAddr),
    Socks4(ProxyAddr),
    Socks5(ProxyAddr),
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("DIRECT"),
            Self::Proxy(addr) => write!(f, "PROXY {addr}"),
            Self::Https(addr) => write!(f, "HTTPS {addr}"),
            Self::Socks(addr) => write!(f, "SOCKS {addr}"),
            Self::Socks4(addr) => write!(f, "SOCKS4 {addr}"),
            Self::Socks5(addr) => write!(f, "SOCKS5 {addr}"),
        }
    }
}

/// The entries of a result, in order, and the ones that could not be read.
#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub routes: Vec<Route>,
    pub ignored: Vec<String>,
}

/// Reads a result such as `PROXY a:8080; PROXY b:3128; DIRECT`.
///
/// Entries are separated by semicolons and the keyword is not case sensitive.
/// An entry that does not make sense is skipped, and reported in `ignored`, so
/// one bad entry in a failover list does not lose the good ones.
pub fn parse(result: &str) -> Parsed {
    let mut routes = Vec::new();
    let mut ignored = Vec::new();
    for entry in result.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match parse_entry(entry) {
            Some(route) => routes.push(route),
            None => ignored.push(entry.to_owned()),
        }
    }
    Parsed { routes, ignored }
}

fn parse_entry(entry: &str) -> Option<Route> {
    let (keyword, rest) = entry
        .split_once(char::is_whitespace)
        .map_or((entry, ""), |(keyword, rest)| (keyword, rest.trim()));
    let keyword = keyword.to_ascii_uppercase();
    if keyword == "DIRECT" {
        return rest.is_empty().then_some(Route::Direct);
    }
    let (build, default_port): (fn(ProxyAddr) -> Route, u16) = match keyword.as_str() {
        "PROXY" | "HTTP" => (Route::Proxy, 80),
        "HTTPS" => (Route::Https, 443),
        "SOCKS" => (Route::Socks, 1080),
        "SOCKS4" => (Route::Socks4, 1080),
        "SOCKS5" => (Route::Socks5, 1080),
        _ => return None,
    };
    parse_address(rest, default_port).map(build)
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`.
fn parse_address(text: &str, default_port: u16) -> Option<ProxyAddr> {
    if text.is_empty() || text.contains(char::is_whitespace) {
        return None;
    }
    let (host, port) = if let Some(after_bracket) = text.strip_prefix('[') {
        let (host, rest) = after_bracket.split_once(']')?;
        let port = match rest {
            "" => None,
            _ => Some(rest.strip_prefix(':')?),
        };
        (host, port)
    } else {
        match text.rsplit_once(':') {
            // A second colon means a bare IPv6 address, which needs brackets.
            Some((host, _)) if host.contains(':') => return None,
            Some((host, port)) => (host, Some(port)),
            None => (text, None),
        }
    };
    let port = match port {
        None => default_port,
        Some(port) => port.parse::<u16>().ok().filter(|port| *port != 0)?,
    };
    let valid = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':'));
    valid.then(|| ProxyAddr {
        host: host.to_owned(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(host: &str, port: u16) -> ProxyAddr {
        ProxyAddr {
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn reads_a_failover_list() {
        let parsed = parse("PROXY a.example.com:8080; PROXY 10.0.0.2:3128 ; DIRECT");
        assert_eq!(
            parsed.routes,
            [
                Route::Proxy(proxy("a.example.com", 8080)),
                Route::Proxy(proxy("10.0.0.2", 3128)),
                Route::Direct
            ]
        );
        assert!(parsed.ignored.is_empty());
    }

    #[test]
    fn the_keyword_is_not_case_sensitive_and_blanks_do_not_matter() {
        let parsed = parse("  proxy  p:80 ;;  Direct;  ");
        assert_eq!(parsed.routes, [Route::Proxy(proxy("p", 80)), Route::Direct]);
    }

    #[test]
    fn every_keyword_is_understood() {
        let parsed = parse("HTTP a:1; HTTPS b:2; SOCKS c:3; SOCKS4 d:4; SOCKS5 e:5");
        assert_eq!(
            parsed.routes,
            [
                Route::Proxy(proxy("a", 1)),
                Route::Https(proxy("b", 2)),
                Route::Socks(proxy("c", 3)),
                Route::Socks4(proxy("d", 4)),
                Route::Socks5(proxy("e", 5)),
            ]
        );
    }

    #[test]
    fn a_missing_port_takes_the_default_of_the_kind() {
        let parsed = parse("PROXY a; HTTPS b; SOCKS5 c");
        assert_eq!(
            parsed.routes,
            [
                Route::Proxy(proxy("a", 80)),
                Route::Https(proxy("b", 443)),
                Route::Socks5(proxy("c", 1080)),
            ]
        );
    }

    #[test]
    fn ipv6_addresses_need_brackets() {
        let parsed = parse("PROXY [2001:db8::1]:8080; PROXY [::1]; PROXY 2001:db8::1");
        assert_eq!(
            parsed.routes,
            [
                Route::Proxy(proxy("2001:db8::1", 8080)),
                Route::Proxy(proxy("::1", 80))
            ]
        );
        assert_eq!(parsed.ignored, ["PROXY 2001:db8::1"]);
    }

    #[test]
    fn entries_that_make_no_sense_are_skipped_and_reported() {
        let parsed = parse(
            "PROXY; PROXY a:0; PROXY a:99999; PROXY a:b; PROXY a b; DIRECT x; FOO a:1; PROXY ok:1",
        );
        assert_eq!(parsed.routes, [Route::Proxy(proxy("ok", 1))]);
        assert_eq!(parsed.ignored.len(), 7);
    }

    #[test]
    fn an_empty_result_has_no_routes() {
        assert!(parse("").routes.is_empty());
        assert!(parse(" ; ; ").routes.is_empty());
    }

    #[test]
    fn routes_print_the_way_they_are_written() {
        let text = "DIRECT";
        assert_eq!(parse(text).routes[0].to_string(), text);
        assert_eq!(
            Route::Proxy(proxy("2001:db8::1", 8080)).to_string(),
            "PROXY [2001:db8::1]:8080"
        );
    }
}
