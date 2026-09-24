//! Header fields that must not be forwarded.

use hyper::header::{CONNECTION, HeaderMap, HeaderName};

/// Fields that apply to a single connection (RFC 9110 section 7.6.1) plus the
/// proxy authentication fields, which are meant for this proxy only.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

/// Removes the hop-by-hop fields, including any field named by `Connection`.
pub(super) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named_by_connection: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();

    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    for name in named_by_connection {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;

    use super::*;

    fn headers(fields: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in fields {
            map.append(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        map
    }

    #[test]
    fn removes_hop_by_hop_and_proxy_credentials() {
        let mut map = headers(&[
            ("connection", "keep-alive"),
            ("proxy-connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-authorization", "Basic c2VjcmV0"),
            ("transfer-encoding", "chunked"),
            ("host", "example.com"),
            ("x-keep", "yes"),
        ]);
        strip_hop_by_hop(&mut map);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("host"));
        assert!(map.contains_key("x-keep"));
    }

    #[test]
    fn removes_fields_named_by_connection() {
        let mut map = headers(&[
            ("connection", "close, X-Private"),
            ("connection", "x-other"),
            ("x-private", "1"),
            ("x-other", "2"),
            ("x-public", "3"),
        ]);
        strip_hop_by_hop(&mut map);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("x-public"));
    }

    #[test]
    fn ignores_malformed_connection_tokens() {
        let mut map = headers(&[("connection", "close, , bad token"), ("x-public", "1")]);
        strip_hop_by_hop(&mut map);
        assert!(map.contains_key("x-public"));
    }
}
