//! Negotiate (SPNEGO) authentication to a parent proxy, with the Kerberos
//! ticket of the logged-in user: no password or hash is kept.
//!
//! The scheme is described in RFC 4559 for servers; a proxy uses
//! `Proxy-Authenticate` and `Proxy-Authorization` in place of
//! `WWW-Authenticate` and `Authorization` (RFC 9110, section 11.7).
//!
//! With Kerberos the client needs no challenge, so the token can go with the
//! first request on a connection. When Kerberos is not possible, the system may
//! fall back to NTLM inside Negotiate (Windows does, for instance, away from the
//! domain), and that takes a second round: the parent answers the first token
//! with a `407` and a token of its own, and the client answers that. A
//! [`SecurityContext`] keeps what the system needs between the two rounds. Like
//! NTLM, Negotiate authenticates the connection.

use std::fmt;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_PAD_INDIFFERENT};
use hyper::header::HeaderValue;

use super::{AuthError, offers};
use crate::config::Credentials;

const SCHEME: &str = "Negotiate";

/// What one round of a Negotiate exchange gives.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    /// What to send to the parent, if there is anything to send.
    pub token: Option<Vec<u8>>,
    /// Whether the security context is established: nothing more is expected
    /// from the parent. With Kerberos it is, after the first token; when the
    /// system falls back to NTLM, it is not.
    pub complete: bool,
}

/// The security context with one service, which the system keeps between the
/// rounds of an exchange. There is one for every connection to be authenticated.
pub trait SecurityContext: Send + fmt::Debug {
    /// The next round: `from_parent` is the token the parent sent, or `None`
    /// for the first. It may block, as a ticket is fetched from the KDC.
    fn step(&mut self, from_parent: Option<&[u8]>) -> Result<Step, AuthError>;
}

/// Makes the tokens that prove who the user is to a service.
pub trait TokenSource: Send + Sync + fmt::Debug {
    /// The token that opens a security context with `service`, made from the
    /// ticket of the logged-in user. It may block: the ticket for a new
    /// service is fetched from the KDC.
    ///
    /// `service` is `HTTP@host`, or a Kerberos principal like
    /// `HTTP/host@REALM` when it holds a `/`.
    fn token(&self, service: &str) -> Result<Vec<u8>, AuthError>;

    /// Starts an exchange with `service`. The default is one round: the token,
    /// and nothing to expect from the parent. A source that can go on (the
    /// system's) says so by overriding this.
    fn start(&self, service: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
        Ok(Box::new(OneRound(Some(self.token(service)?))))
    }
}

/// The exchange of a source that has one token and no more.
#[derive(Debug)]
struct OneRound(Option<Vec<u8>>);

impl SecurityContext for OneRound {
    fn step(&mut self, from_parent: Option<&[u8]>) -> Result<Step, AuthError> {
        match (self.0.take(), from_parent) {
            (Some(token), None) => Ok(Step {
                token: Some(token),
                complete: true,
            }),
            _ => Err(AuthError::Exchange {
                service: String::new(),
                reason: "the parent sent a token, and none was expected".to_owned(),
            }),
        }
    }
}

/// Produces the `Proxy-Authorization` values of a Negotiate exchange. One
/// instance serves every connection.
#[derive(Debug)]
pub struct NegotiateAuthenticator {
    tokens: Arc<dyn TokenSource>,
    service: Option<String>,
}

impl NegotiateAuthenticator {
    pub fn new(credentials: &Credentials, tokens: Arc<dyn TokenSource>) -> Self {
        Self {
            tokens,
            service: credentials.spn.clone(),
        }
    }

    pub fn tokens(&self) -> Arc<dyn TokenSource> {
        self.tokens.clone()
    }

    /// The service to ask a ticket for: the configured one, else the HTTP
    /// service of the parent's host.
    pub fn service_for(&self, parent_host: &str) -> String {
        self.service
            .clone()
            .unwrap_or_else(|| format!("HTTP@{parent_host}"))
    }
}

/// `Negotiate <base64>`, marked sensitive so it never shows up in debug output.
pub fn header(token: &[u8]) -> HeaderValue {
    let mut value = HeaderValue::from_str(&format!("{SCHEME} {}", STANDARD.encode(token)))
        .expect("base64 text is a valid header value");
    value.set_sensitive(true);
    value
}

/// Why a parent answered a Negotiate token with another `407`.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// It does not offer Negotiate at all.
    NotOffered { offered: Vec<String> },
    /// It answered with a token of its own, asking for another round.
    AnotherRound,
    /// It offers Negotiate and did not accept the ticket.
    Rejected,
}

/// Reads the `Proxy-Authenticate` fields of that `407`.
pub fn refusal<'a>(fields: impl IntoIterator<Item = &'a HeaderValue>) -> Refusal {
    let offers = offers::all(fields);
    match offers
        .iter()
        .find(|offer| offer.scheme.eq_ignore_ascii_case(SCHEME))
    {
        None => Refusal::NotOffered {
            offered: offers::names(&offers),
        },
        Some(offer) if offer.token.is_some() => Refusal::AnotherRound,
        Some(_) => Refusal::Rejected,
    }
}

/// What the system made of a request for a token, for finding out why
/// authentication does not work.
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

/// The token the parent sent with its `407`, if it sent one.
pub fn challenge<'a>(fields: impl IntoIterator<Item = &'a HeaderValue>) -> Option<Vec<u8>> {
    let offers = offers::all(fields);
    let offer = offers
        .iter()
        .find(|offer| offer.scheme.eq_ignore_ascii_case(SCHEME))?;
    STANDARD_PAD_INDIFFERENT.decode(offer.token?).ok()
}

/// The tokens of the system: the ticket cache of the logged-in user, through
/// the GSS-API of the operating system.
pub fn system_tokens() -> Result<Arc<dyn TokenSource>, AuthError> {
    system::tokens()
}

#[cfg(unix)]
mod system {
    use std::sync::Arc;

    // `is_complete` comes from the library's trait of the same name as ours.
    use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext as _};
    use libgssapi::name::Name;
    use libgssapi::oid::{GSS_MECH_SPNEGO, GSS_NT_HOSTBASED_SERVICE, GSS_NT_KRB5_PRINCIPAL};

    use super::{SecurityContext, Step, TokenSource};
    use crate::auth::AuthError;

    pub(super) fn tokens() -> Result<Arc<dyn TokenSource>, AuthError> {
        Ok(Arc::new(Gss))
    }

    /// The GSS-API of the system: Kerberos through SPNEGO, with the default
    /// credentials, which are the ticket cache of the logged-in user.
    #[derive(Debug)]
    struct Gss;

    impl TokenSource for Gss {
        fn token(&self, service: &str) -> Result<Vec<u8>, AuthError> {
            self.start(service)?
                .step(None)?
                .token
                .ok_or_else(|| AuthError::NoTicket {
                    service: service.to_owned(),
                    reason: "the system produced no token".to_owned(),
                })
        }

        fn start(&self, service: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
            let fail = |reason: String| AuthError::NoTicket {
                service: service.to_owned(),
                reason,
            };
            let kind = if service.contains('/') {
                GSS_NT_KRB5_PRINCIPAL
            } else {
                GSS_NT_HOSTBASED_SERVICE
            };
            let name =
                Name::new(service.as_bytes(), Some(kind)).map_err(|err| fail(err.to_string()))?;
            Ok(Box::new(GssContext {
                context: ClientCtx::new(None, name, CtxFlags::empty(), Some(GSS_MECH_SPNEGO)),
                service: service.to_owned(),
            }))
        }
    }

    struct GssContext {
        context: ClientCtx,
        service: String,
    }

    impl std::fmt::Debug for GssContext {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GssContext")
                .field("service", &self.service)
                .finish_non_exhaustive()
        }
    }

    impl SecurityContext for GssContext {
        fn step(&mut self, from_parent: Option<&[u8]>) -> Result<Step, AuthError> {
            let token =
                self.context
                    .step(from_parent, None)
                    .map_err(|err| AuthError::Exchange {
                        service: self.service.clone(),
                        reason: err.to_string(),
                    })?;
            Ok(Step {
                token: token.map(|token| token.to_vec()),
                complete: self.context.is_complete(),
            })
        }
    }
}

#[cfg(not(unix))]
mod system {
    use std::sync::Arc;

    use super::TokenSource;
    use crate::auth::AuthError;

    pub(super) fn tokens() -> Result<Arc<dyn TokenSource>, AuthError> {
        Err(AuthError::NegotiateUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;

    #[derive(Debug)]
    struct Fixed;

    impl TokenSource for Fixed {
        fn token(&self, service: &str) -> Result<Vec<u8>, AuthError> {
            Ok(format!("ticket for {service}").into_bytes())
        }
    }

    fn credentials(spn: Option<&str>) -> Credentials {
        Credentials {
            method: AuthMethod::Negotiate,
            username: String::new(),
            domain: String::new(),
            workstation: None,
            secret: None,
            spn: spn.map(str::to_owned),
        }
    }

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

    fn fields(values: &[&str]) -> Vec<HeaderValue> {
        values
            .iter()
            .map(|value| HeaderValue::from_str(value).unwrap())
            .collect()
    }

    #[test]
    fn the_service_is_the_http_service_of_the_parent_unless_configured() {
        let by_default = NegotiateAuthenticator::new(&credentials(None), Arc::new(Fixed));
        assert_eq!(
            by_default.service_for("proxy.example.com"),
            "HTTP@proxy.example.com"
        );

        let configured = NegotiateAuthenticator::new(
            &credentials(Some("HTTP/alias.example.com@EXAMPLE.COM")),
            Arc::new(Fixed),
        );
        assert_eq!(
            configured.service_for("proxy.example.com"),
            "HTTP/alias.example.com@EXAMPLE.COM"
        );
    }

    #[test]
    fn the_header_carries_the_token_and_stays_out_of_debug_output() {
        let value = header(b"ticket");
        assert_eq!(value.to_str().unwrap(), "Negotiate dGlja2V0");
        assert_eq!(format!("{value:?}"), "Sensitive");
    }

    #[test]
    fn tells_why_a_parent_refused_the_token() {
        assert_eq!(
            refusal(&fields(&["NTLM", "Basic realm=\"x\""])),
            Refusal::NotOffered {
                offered: vec!["NTLM".to_owned(), "Basic".to_owned()]
            }
        );
        assert_eq!(refusal(&fields(&["NEGOTIATE", "NTLM"])), Refusal::Rejected);
        assert_eq!(refusal(&fields(&["Negotiate YIIB"])), Refusal::AnotherRound);
        assert_eq!(
            refusal(&fields(&[])),
            Refusal::NotOffered { offered: vec![] }
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_system_tokens_are_available_on_unix() {
        assert!(system_tokens().is_ok());
    }

    #[cfg(not(unix))]
    #[test]
    fn the_system_tokens_are_not_available_elsewhere_yet() {
        assert!(matches!(
            system_tokens(),
            Err(AuthError::NegotiateUnavailable)
        ));
    }
}
