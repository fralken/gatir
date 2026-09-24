//! Request header fields added or replaced on every forwarded request.
//!
//! Values may hold tokens, so they are treated as secrets: they are marked
//! sensitive, never shown by `Debug` or the configuration summary, and never
//! quoted in an error message.

use std::collections::BTreeMap;

use hyper::header::{HeaderName, HeaderValue};
use secrecy::ExposeSecret;

use super::ConfigError;
use super::credentials::SecretValue;

/// Fields that gatir manages itself, or that would break how the message is
/// framed or routed. They cannot be set from the configuration.
const RESERVED: [&str; 11] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

/// A header field to set, with its value marked sensitive.
pub type HeaderRule = (HeaderName, HeaderValue);

pub(super) fn parse(raw: BTreeMap<String, SecretValue>) -> Result<Vec<HeaderRule>, ConfigError> {
    let mut rules: Vec<HeaderRule> = Vec::with_capacity(raw.len());
    for (name, value) in raw {
        let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            ConfigError::invalid(format!("headers: \"{name}\" is not a valid header name"))
        })?;
        if RESERVED.contains(&header.as_str()) {
            return Err(ConfigError::invalid(format!(
                "headers: \"{name}\" is managed by gatir and cannot be set"
            )));
        }
        if rules.iter().any(|(existing, _)| *existing == header) {
            return Err(ConfigError::invalid(format!(
                "headers: \"{name}\" is set more than once (names are case-insensitive)"
            )));
        }
        let mut value = HeaderValue::from_str(value.0.expose_secret()).map_err(|_| {
            ConfigError::invalid(format!(
                "headers: the value of \"{name}\" contains characters that are not allowed"
            ))
        })?;
        value.set_sensitive(true);
        rules.push((header, value));
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn raw(entries: &[(&str, &str)]) -> BTreeMap<String, SecretValue> {
        entries
            .iter()
            .map(|(name, value)| {
                (
                    (*name).to_owned(),
                    SecretValue(SecretString::from((*value).to_owned())),
                )
            })
            .collect()
    }

    fn error(entries: &[(&str, &str)]) -> String {
        parse(raw(entries)).unwrap_err().to_string()
    }

    #[test]
    fn accepts_ordinary_fields() {
        let rules = parse(raw(&[
            ("User-Agent", "corp/1.0"),
            ("X-Requested-By", "gatir"),
        ]))
        .unwrap();
        let names: Vec<&str> = rules.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["user-agent", "x-requested-by"]);
        assert!(rules.iter().all(|(_, value)| value.is_sensitive()));
    }

    #[test]
    fn rejects_the_fields_gatir_manages() {
        for name in [
            "Host",
            "content-length",
            "Transfer-Encoding",
            "Connection",
            "Proxy-Connection",
            "Keep-Alive",
            "TE",
            "Trailer",
            "Upgrade",
            "Proxy-Authorization",
            "Proxy-Authenticate",
        ] {
            let text = error(&[(name, "x")]);
            assert!(text.contains("managed by gatir"), "{name}: {text}");
        }
    }

    #[test]
    fn rejects_invalid_names_and_values_without_quoting_the_value() {
        assert!(error(&[("Bad Name", "x")]).contains("not a valid header name"));
        assert!(error(&[("", "x")]).contains("not a valid header name"));

        let text = error(&[("X-Token", "secret-token\r\nInjected: yes")]);
        assert!(text.contains("X-Token"), "{text}");
        assert!(!text.contains("secret-token"), "{text}");
    }

    #[test]
    fn rejects_the_same_name_written_with_different_case() {
        let text = error(&[("x-thing", "1"), ("X-Thing", "2")]);
        assert!(text.contains("more than once"), "{text}");
    }
}
