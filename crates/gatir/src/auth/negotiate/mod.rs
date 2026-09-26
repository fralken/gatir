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

mod diagnose;
#[cfg(unix)]
mod gss;
mod sspi;

pub use diagnose::{Diagnosis, diagnose};

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

    /// Starts an exchange with `service` in NTLM alone, with the identity of
    /// the logged-on user: for a parent that offers NTLM and not Negotiate.
    /// The tokens are NTLM messages, which go with the `NTLM` scheme. `None` if
    /// the system cannot do that without a password: Windows can, the GSS-API
    /// of Unix cannot.
    fn start_ntlm(&self, _service: &str) -> Result<Option<Box<dyn SecurityContext>>, AuthError> {
        Ok(None)
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
pub struct Authenticator {
    tokens: Arc<dyn TokenSource>,
    service: Option<String>,
}

impl Authenticator {
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

/// The token the parent sent with its `407`, if it sent one.
pub fn challenge<'a>(fields: impl IntoIterator<Item = &'a HeaderValue>) -> Option<Vec<u8>> {
    let offers = offers::all(fields);
    let offer = offers
        .iter()
        .find(|offer| offer.scheme.eq_ignore_ascii_case(SCHEME))?;
    STANDARD_PAD_INDIFFERENT.decode(offer.token?).ok()
}

/// The tokens of the system: on Unix the ticket cache of the logged-in user,
/// through the GSS-API of the operating system.
#[cfg(unix)]
pub fn system_tokens() -> Result<Arc<dyn TokenSource>, AuthError> {
    Ok(gss::tokens())
}

/// The tokens of the system: on Windows SSPI, the logged-on user, with Kerberos
/// when it is possible and NTLM when it is not, and no password kept anywhere.
#[cfg(windows)]
pub fn system_tokens() -> Result<Arc<dyn TokenSource>, AuthError> {
    Ok(sspi::tokens())
}

/// The tokens of the system: there are none on this platform yet.
#[cfg(not(any(unix, windows)))]
pub fn system_tokens() -> Result<Arc<dyn TokenSource>, AuthError> {
    Err(AuthError::NegotiateUnavailable)
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

    fn fields(values: &[&str]) -> Vec<HeaderValue> {
        values
            .iter()
            .map(|value| HeaderValue::from_str(value).unwrap())
            .collect()
    }

    #[test]
    fn the_service_is_the_http_service_of_the_parent_unless_configured() {
        let by_default = Authenticator::new(&credentials(None), Arc::new(Fixed));
        assert_eq!(
            by_default.service_for("proxy.example.com"),
            "HTTP@proxy.example.com"
        );

        let configured = Authenticator::new(
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
