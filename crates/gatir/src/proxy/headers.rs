//! Header fields that must not be forwarded.

use hyper::header::{CONNECTION, HeaderMap, HeaderName};

use crate::config::HeaderRule;

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

/// Sets the configured fields, replacing any the client sent.
pub(super) fn apply_rules(headers: &mut HeaderMap, rules: &[HeaderRule]) {
    for (name, value) in rules {
        headers.insert(name.clone(), value.clone());
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
    fn fuzz_what_a_connection_field_names() {
        use gatir_testkit::fuzz::each_variant;

        let seeds: [&[u8]; 4] = [
            b"keep-alive, X-Drop",
            b"close",
            b"Upgrade, x-drop , , X-Other",
            b"x-drop,x-keep2",
        ];
        each_variant(&seeds, 20_000, |value| {
            let Ok(value) = HeaderValue::from_bytes(value) else {
                return;
            };
            let mut map = headers(&[
                ("x-drop", "1"),
                ("x-other", "2"),
                ("host", "example.com"),
                ("content-length", "0"),
                ("x-keep2", "3"),
            ]);
            let named = value.to_str().unwrap_or_default().to_owned();
            map.append(CONNECTION, value);
            strip_hop_by_hop(&mut map);
            // Whatever `Connection` says, what only the two ends need stays,
            // and the field itself is gone.
            assert!(map.contains_key("host") && map.contains_key("content-length"));
            assert!(!map.contains_key(CONNECTION));
            for name in HOP_BY_HOP {
                assert!(!map.contains_key(name), "{name}");
            }
            // A field goes if `Connection` names it, and only then.
            for name in ["x-drop", "x-other", "x-keep2"] {
                let is_named = named
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case(name));
                assert_eq!(map.contains_key(name), !is_named, "{name} in {named:?}");
            }
        });
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
    fn configured_fields_replace_or_add() {
        let mut map = headers(&[("user-agent", "client"), ("x-keep", "yes")]);
        let rules = vec![
            (
                HeaderName::from_static("user-agent"),
                HeaderValue::from_static("corp"),
            ),
            (
                HeaderName::from_static("x-added"),
                HeaderValue::from_static("1"),
            ),
        ];
        apply_rules(&mut map, &rules);
        assert_eq!(map["user-agent"], "corp");
        assert_eq!(map["x-added"], "1");
        assert_eq!(map["x-keep"], "yes");
        assert_eq!(map.get_all("user-agent").iter().count(), 1);
    }

    #[test]
    fn ignores_malformed_connection_tokens() {
        let mut map = headers(&[("connection", "close, , bad token"), ("x-public", "1")]);
        strip_hop_by_hop(&mut map);
        assert!(map.contains_key("x-public"));
    }
}
