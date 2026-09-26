//! What the system made of a request for a token, for finding out why
//! authentication does not work (`gatir negotiate`).

use super::TokenSource;
use crate::auth::AuthError;

#[derive(Debug, PartialEq, Eq)]
pub struct Diagnosis {
    pub token_bytes: usize,
    /// The mechanisms the token offers, in the order it lists them: the first
    /// is the one the system tries.
    pub mechanisms: Vec<&'static str>,
    /// Whether nothing more is expected from the parent.
    pub complete: bool,
}

/// Asks `source` for the first token for `service`, and says what it is.
pub fn diagnose(source: &dyn TokenSource, service: &str) -> Result<Diagnosis, AuthError> {
    let step = source.start(service)?.step(None)?;
    let token = step.token.ok_or_else(|| AuthError::NoTicket {
        service: service.to_owned(),
        reason: "the system produced no token".to_owned(),
    })?;
    Ok(Diagnosis {
        token_bytes: token.len(),
        mechanisms: mechanisms(&token),
        complete: step.complete,
    })
}

/// The security mechanisms named in a token, by their identifiers (object
/// identifiers in DER): a SPNEGO token lists them, and an NTLM message is one
/// of them without the wrapping.
fn mechanisms(token: &[u8]) -> Vec<&'static str> {
    const KNOWN: [(&str, &[u8]); 3] = [
        (
            "Kerberos",
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
            ],
        ),
        (
            "Kerberos (Microsoft)",
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
            ],
        ),
        (
            "NTLM",
            &[
                0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
            ],
        ),
    ];
    let mut found: Vec<(usize, &'static str)> = KNOWN
        .iter()
        .filter_map(|(name, pattern)| {
            token
                .windows(pattern.len())
                .position(|window| window == *pattern)
                .map(|at| (at, *name))
        })
        .collect();
    if token.starts_with(b"NTLMSSP\0") {
        found.push((0, "NTLM"));
    }
    found.sort_by_key(|(at, _)| *at);
    found.dedup_by_key(|(_, name)| *name);
    found.into_iter().map(|(_, name)| name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_told_by_the_mechanisms_it_names() {
        let kerberos = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
        let ms_kerberos = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
        let ntlm = [
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
        ];
        let spnego = |parts: &[&[u8]]| {
            let mut token = vec![
                0x60, 0x82, 0x01, 0x00, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
            ];
            for part in parts {
                token.extend_from_slice(part);
            }
            token
        };
        // In the order the token lists them.
        assert_eq!(mechanisms(&spnego(&[&kerberos])), ["Kerberos"]);
        assert_eq!(
            mechanisms(&spnego(&[&ms_kerberos, &kerberos, &ntlm])),
            ["Kerberos (Microsoft)", "Kerberos", "NTLM"]
        );
        assert_eq!(mechanisms(&spnego(&[&ntlm])), ["NTLM"]);
        assert_eq!(mechanisms(b"NTLMSSP\0\x01\0\0\0"), ["NTLM"]);
        assert!(mechanisms(b"nothing to see").is_empty());
        assert!(mechanisms(&[]).is_empty());
    }

    #[test]
    fn a_source_is_diagnosed_by_its_first_token() {
        #[derive(Debug)]
        struct Says(&'static [u8]);
        impl TokenSource for Says {
            fn token(&self, _service: &str) -> Result<Vec<u8>, AuthError> {
                Ok(self.0.to_vec())
            }
        }
        let diagnosis = diagnose(&Says(b"NTLMSSP\0\x01\0\0\0"), "HTTP@proxy").unwrap();
        assert_eq!(
            diagnosis,
            Diagnosis {
                token_bytes: 12,
                mechanisms: vec!["NTLM"],
                complete: true
            }
        );
        #[derive(Debug)]
        struct Fails;
        impl TokenSource for Fails {
            fn token(&self, service: &str) -> Result<Vec<u8>, AuthError> {
                Err(AuthError::NoTicket {
                    service: service.to_owned(),
                    reason: "no ticket".to_owned(),
                })
            }
        }
        assert!(
            diagnose(&Fails, "HTTP@proxy")
                .unwrap_err()
                .to_string()
                .contains("no ticket")
        );
    }
}
