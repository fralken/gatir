//! Authentication to the parent proxy.
//!
//! Together with `config`, this is where secrets are handled.

pub mod negotiate;
pub mod ntlm;
mod offers;

use std::sync::Arc;

pub use negotiate::{
    Diagnosis, Refusal, SecurityContext, Step, TokenSource, challenge, diagnose,
    header as negotiate_header, refusal, system_tokens,
};

use crate::config::{AuthMethod, Credentials};
use ntlm::MessageError;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("this is not an NTLM method")]
    NotNtlm,
    #[error("the credentials have neither a password nor an NT hash")]
    NoSecret,
    #[error("the parent proxy does not offer NTLM authentication{}", offered_list(.offered))]
    NtlmNotOffered { offered: Vec<String> },
    #[error("the parent proxy did not send an NTLM challenge")]
    NoChallenge,
    #[error("the parent proxy sent an invalid NTLM challenge: {0}")]
    BadChallenge(String),
    #[error("cannot build the NTLM message: {0}")]
    Message(#[from] MessageError),
    #[error("cannot get random bytes for the NTLM response: {0}")]
    Entropy(getrandom::Error),
    #[error("Negotiate is not available on this platform yet")]
    NegotiateUnavailable,
    #[error("Negotiate needs the Kerberos library of the system, which cannot be loaded: {reason}")]
    KerberosLibrary { reason: String },
    #[error("cannot get a Kerberos ticket for {service}: {reason}")]
    NoTicket { service: String, reason: String },
    #[error("the parent proxy does not offer Negotiate authentication{}", offered_list(.offered))]
    NegotiateNotOffered { offered: Vec<String> },
    #[error("the Negotiate exchange with {service} went wrong: {reason}")]
    Exchange { service: String, reason: String },
}

/// The authentication schemes named in a `407`/`401`'s challenge fields, in the
/// order they were offered: for reporting what a server offers, regardless of
/// which of them gatir itself can use.
pub fn offered_schemes<'a>(
    fields: impl IntoIterator<Item = &'a hyper::header::HeaderValue>,
) -> Vec<String> {
    offers::names(&offers::all(fields))
}

fn offered_list(offered: &[String]) -> String {
    if offered.is_empty() {
        String::new()
    } else {
        format!(" (it offers: {})", offered.join(", "))
    }
}

/// How to authenticate to a parent proxy, made from the configured credentials.
#[derive(Debug)]
pub enum Authenticator {
    /// A password-derived response to a challenge from the proxy.
    Ntlm(ntlm::Authenticator),
    /// The Kerberos ticket of the logged-in user.
    Negotiate(negotiate::Authenticator),
}

impl Authenticator {
    pub fn new(credentials: &Credentials) -> Result<Self, AuthError> {
        match credentials.method {
            AuthMethod::Negotiate => Self::with_tokens(credentials, negotiate::system_tokens()?),
            _ => Ok(Self::Ntlm(ntlm::Authenticator::new(credentials)?)),
        }
    }

    /// Like [`Authenticator::new`], taking the Negotiate tokens from `tokens`
    /// instead of the system. For tests, which have no Kerberos ticket.
    pub fn with_tokens(
        credentials: &Credentials,
        tokens: Arc<dyn TokenSource>,
    ) -> Result<Self, AuthError> {
        match credentials.method {
            AuthMethod::Negotiate => Ok(Self::Negotiate(negotiate::Authenticator::new(
                credentials,
                tokens,
            ))),
            _ => Ok(Self::Ntlm(ntlm::Authenticator::new(credentials)?)),
        }
    }
}
