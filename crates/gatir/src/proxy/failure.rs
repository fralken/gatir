//! Reasons a request cannot be served, and connecting to the next hop.

use std::fmt;
use std::io;
use std::time::Duration;

use hyper::header::{HeaderValue, RETRY_AFTER};
use hyper::{Response, StatusCode};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::body::{Body, error_response};
use super::parent_auth::COOLDOWN;
use crate::auth::AuthError;
use crate::pac::PacError;

/// Why opening a TCP connection failed.
#[derive(Debug)]
pub(super) enum ConnectError {
    Timeout,
    Io(io::Error),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("timed out"),
            Self::Io(err) => err.fmt(f),
        }
    }
}

/// One failed attempt to reach a parent proxy.
#[derive(Debug)]
pub(super) struct ParentAttempt {
    pub address: String,
    pub error: ConnectError,
}

#[derive(Debug)]
pub(super) enum Failure {
    BadRequest(&'static str),
    ConnectTimeout(String),
    Connect {
        address: String,
        source: io::Error,
    },
    ParentsUnavailable(Vec<ParentAttempt>),
    Upstream(hyper::Error),
    /// The parent proxy did something unexpected; the text says what.
    Parent(&'static str),
    /// No response came in time from the named party.
    ResponseTimeout(&'static str),
    /// The NTLM exchange with the parent could not be carried out.
    Authentication(AuthError),
    /// The parent answered the credentials with another `407`.
    CredentialsRejected {
        user: String,
    },
    /// The parent refused the credentials recently, so nobody is trying yet.
    CoolingDown(Duration),
    /// The parent offers Negotiate and did not accept the Kerberos ticket.
    TicketRejected {
        service: String,
    },
    /// The PAC script could not say where to send the request.
    Pac(PacError),
    /// The PAC script chose only ways of reaching the destination that gatir
    /// cannot use, such as a SOCKS proxy.
    PacUnsupported(String),
    /// A connection the parent had authenticated asked for authentication
    /// again, and the request cannot be sent twice.
    AuthenticationLapsed,
}

impl From<AuthError> for Failure {
    fn from(error: AuthError) -> Self {
        Self::Authentication(error)
    }
}

impl Failure {
    /// The status an HTTP client is given, and what it is told.
    fn status_and_message(&self) -> (StatusCode, String) {
        let bad_gateway = |message: String| (StatusCode::BAD_GATEWAY, message);
        match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, (*message).to_owned()),
            Self::ConnectTimeout(address) => (
                StatusCode::GATEWAY_TIMEOUT,
                format!("Timed out connecting to {address}"),
            ),
            Self::Connect { address, source } => {
                bad_gateway(format!("Cannot connect to {address}: {source}"))
            }
            Self::ParentsUnavailable(attempts) => {
                let all_timed_out = attempts
                    .iter()
                    .all(|attempt| matches!(attempt.error, ConnectError::Timeout));
                let status = if all_timed_out {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::BAD_GATEWAY
                };
                let tried = attempts
                    .iter()
                    .map(|attempt| format!("{} ({})", attempt.address, attempt.error))
                    .collect::<Vec<_>>()
                    .join("; ");
                (status, format!("No parent proxy is reachable: {tried}"))
            }
            Self::Upstream(err) => {
                bad_gateway(format!("Invalid response from the upstream server: {err}"))
            }
            Self::Parent(message) => bad_gateway((*message).to_owned()),
            Self::ResponseTimeout(who) => (
                StatusCode::GATEWAY_TIMEOUT,
                format!("Timed out waiting for a response from {who}"),
            ),
            Self::Authentication(err) => {
                bad_gateway(format!("Cannot authenticate to the parent proxy: {err}"))
            }
            Self::CredentialsRejected { user } => bad_gateway(format!(
                "The parent proxy rejected the credentials of {user}. Check the user name, \
                 domain and password. gatir will not try again for {} minutes, so that the \
                 account does not get locked.",
                COOLDOWN.as_secs() / 60
            )),
            Self::Pac(err) => bad_gateway(format!(
                "The PAC script could not tell where to send this request: {err}"
            )),
            Self::PacUnsupported(chosen) => bad_gateway(format!(
                "The PAC script chose only ways of reaching the destination that gatir does not \
                 support: {chosen}"
            )),
            Self::TicketRejected { service } => bad_gateway(format!(
                "The parent proxy did not accept the Kerberos ticket for {service}. Check that \
                 the ticket is valid (klist), that the clock is right, and that this is the \
                 name the proxy is registered under (credentials.spn)."
            )),
            Self::CoolingDown(remaining) => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "The parent proxy rejected the credentials recently. Not trying again for \
                     {} seconds, so that the account does not get locked.",
                    remaining.as_secs() + 1
                ),
            ),
            Self::AuthenticationLapsed => bad_gateway(
                "The parent proxy asked for authentication again on a connection it had \
                 authenticated, and this request cannot be sent twice. Try again."
                    .to_owned(),
            ),
        }
    }

    /// What went wrong, in words: for the log, when the client speaks a
    /// protocol that has no place for an HTTP answer.
    pub(super) fn message(&self) -> String {
        self.status_and_message().1
    }

    pub(super) fn into_response(self) -> Response<Body> {
        let (status, message) = self.status_and_message();
        let mut response = error_response(status, message, matches!(self, Self::BadRequest(_)));
        if let Self::CoolingDown(remaining) = &self {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(remaining.as_secs() + 1));
        }
        response
    }
}

/// Opens a TCP connection to `address` (`host:port`), giving up after `limit`.
pub(super) async fn try_connect(address: &str, limit: Duration) -> Result<TcpStream, ConnectError> {
    let stream = match timeout(limit, TcpStream::connect(address)).await {
        Err(_) => return Err(ConnectError::Timeout),
        Ok(Err(source)) => return Err(ConnectError::Io(source)),
        Ok(Ok(stream)) => stream,
    };
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(%err, "cannot set TCP_NODELAY on the upstream connection");
    }
    Ok(stream)
}

/// A failure to connect to `address`, as something to tell the client.
pub(super) fn connect_failure(address: &str, error: ConnectError) -> Failure {
    match error {
        ConnectError::Timeout => Failure::ConnectTimeout(address.to_owned()),
        ConnectError::Io(source) => Failure::Connect {
            address: address.to_owned(),
            source,
        },
    }
}
