//! Reading the `Proxy-Authenticate` fields of a `407`.

use hyper::header::HeaderValue;

/// One challenge of a `Proxy-Authenticate` field: a scheme and what follows it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Offer<'a> {
    pub scheme: &'a str,
    pub token: Option<&'a str>,
}

/// Every challenge in the fields, in the order they were offered. A field may
/// hold several, separated by commas.
pub(super) fn all<'a>(fields: impl IntoIterator<Item = &'a HeaderValue>) -> Vec<Offer<'a>> {
    fields
        .into_iter()
        .filter_map(|field| field.to_str().ok())
        .flat_map(offers)
        .collect()
}

/// The schemes of `offers`, for a message saying what the proxy does offer.
pub(super) fn names(offers: &[Offer<'_>]) -> Vec<String> {
    offers.iter().map(|offer| offer.scheme.to_owned()).collect()
}

fn offers(field: &str) -> impl Iterator<Item = Offer<'_>> {
    split_outside_quotes(field).into_iter().filter_map(|part| {
        let part = part.trim();
        let (scheme, rest) = part
            .split_once(char::is_whitespace)
            .map_or((part, ""), |(scheme, rest)| (scheme, rest.trim()));
        // A part like `charset="UTF-8"` goes on with the previous challenge; it
        // does not start a new one.
        if scheme.is_empty() || scheme.contains('=') {
            return None;
        }
        Some(Offer {
            scheme,
            token: (!rest.is_empty()).then_some(rest),
        })
    })
}

/// Splits at the commas that are not inside a quoted string.
fn split_outside_quotes(field: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (index, character) in field.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(&field[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&field[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(values: &[&str]) -> Vec<HeaderValue> {
        values
            .iter()
            .map(|value| HeaderValue::from_str(value).unwrap())
            .collect()
    }

    #[test]
    fn reads_one_challenge_per_field() {
        let values = fields(&["NEGOTIATE", "NTLM", "BASIC realm=\"kerberos\""]);
        let found = all(&values);
        assert_eq!(names(&found), ["NEGOTIATE", "NTLM", "BASIC"]);
        assert!(
            found
                .iter()
                .all(|offer| offer.token.is_none() || offer.scheme == "BASIC")
        );
    }

    #[test]
    fn keeps_the_token_that_follows_a_scheme() {
        let values = fields(&["Negotiate YIIB", "NTLM"]);
        assert_eq!(
            all(&values),
            [
                Offer {
                    scheme: "Negotiate",
                    token: Some("YIIB")
                },
                Offer {
                    scheme: "NTLM",
                    token: None
                }
            ]
        );
    }

    #[test]
    fn splits_a_field_holding_several_challenges() {
        let values = fields(&["Basic realm=\"a, b\", charset=\"UTF-8\", NTLM, Negotiate abc="]);
        assert_eq!(names(&all(&values)), ["Basic", "NTLM", "Negotiate"]);
    }

    #[test]
    fn skips_fields_that_are_not_text() {
        let values = vec![HeaderValue::from_bytes(b"NTLM \xff").unwrap()];
        assert!(all(&values).is_empty());
    }
}
