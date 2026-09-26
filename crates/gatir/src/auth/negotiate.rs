//! Negotiate (SPNEGO) authentication to a parent proxy, with the Kerberos
//! ticket of the logged-in user: no password or hash is kept.
//!
//! The scheme is described in RFC 4559 for servers; a proxy uses
//! `Proxy-Authenticate` and `Proxy-Authorization` in place of
//! `WWW-Authenticate` and `Authorization` (RFC 9110, section 11.7).
//!
//! The client needs no challenge, so the token can go with the first request
//! on a connection. Like NTLM, it authenticates the connection.

use std::fmt;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hyper::header::HeaderValue;

use super::{AuthError, offers};
use crate::config::Credentials;

const SCHEME: &str = "Negotiate";

/// Makes the tokens that prove who the user is to a service.
pub trait TokenSource: Send + Sync + fmt::Debug {
    /// The token that opens a security context with `service`, made from the
    /// ticket of the logged-in user. It may block: the ticket for a new
    /// service is fetched from the KDC.
    ///
    /// `service` is `HTTP@host`, or a Kerberos principal like
    /// `HTTP/host@REALM` when it holds a `/`.
    fn token(&self, service: &str) -> Result<Vec<u8>, AuthError>;
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

/// The tokens of the system: the ticket cache of the logged-in user, through
/// the GSS-API of the operating system.
pub fn system_tokens() -> Result<Arc<dyn TokenSource>, AuthError> {
    system::tokens()
}

#[cfg(unix)]
mod system {
    use std::sync::Arc;

    use libgssapi::context::{ClientCtx, CtxFlags};
    use libgssapi::name::Name;
    use libgssapi::oid::{GSS_MECH_SPNEGO, GSS_NT_HOSTBASED_SERVICE, GSS_NT_KRB5_PRINCIPAL};

    use super::TokenSource;
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
            let mut context = ClientCtx::new(None, name, CtxFlags::empty(), Some(GSS_MECH_SPNEGO));
            let token = context
                .step(None, None)
                .map_err(|err| fail(err.to_string()))?
                .ok_or_else(|| fail("the system produced no token".to_owned()))?;
            Ok(token.to_vec())
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
