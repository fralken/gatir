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

/// Why opening a TCP connection failed.
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
pub(super) struct ParentAttempt {
    pub address: String,
    pub error: ConnectError,
}

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
    pub(super) fn into_response(self) -> Response<Body> {
        match self {
            Self::BadRequest(message) => error_response(StatusCode::BAD_REQUEST, message, true),
            Self::ConnectTimeout(address) => error_response(
                StatusCode::GATEWAY_TIMEOUT,
                format!("Timed out connecting to {address}"),
                false,
            ),
            Self::Connect { address, source } => error_response(
                StatusCode::BAD_GATEWAY,
                format!("Cannot connect to {address}: {source}"),
                false,
            ),
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
                error_response(
                    status,
                    format!("No parent proxy is reachable: {tried}"),
                    false,
                )
            }
            Self::Upstream(err) => error_response(
                StatusCode::BAD_GATEWAY,
                format!("Invalid response from the upstream server: {err}"),
                false,
            ),
            Self::Parent(message) => error_response(StatusCode::BAD_GATEWAY, message, false),
            Self::ResponseTimeout(who) => error_response(
                StatusCode::GATEWAY_TIMEOUT,
                format!("Timed out waiting for a response from {who}"),
                false,
            ),
            Self::Authentication(err) => error_response(
                StatusCode::BAD_GATEWAY,
                format!("Cannot authenticate to the parent proxy: {err}"),
                false,
            ),
            Self::CredentialsRejected { user } => error_response(
                StatusCode::BAD_GATEWAY,
                format!(
                    "The parent proxy rejected the credentials of {user}. Check the user name, \
                     domain and password. gatir will not try again for {} minutes, so that the \
                     account does not get locked.",
                    COOLDOWN.as_secs() / 60
                ),
                false,
            ),
            Self::CoolingDown(remaining) => {
                let seconds = remaining.as_secs() + 1;
                let mut response = error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "The parent proxy rejected the credentials recently. Not trying again for \
                         {seconds} seconds, so that the account does not get locked."
                    ),
                    false,
                );
                response
                    .headers_mut()
                    .insert(RETRY_AFTER, HeaderValue::from(seconds));
                response
            }
            Self::AuthenticationLapsed => error_response(
                StatusCode::BAD_GATEWAY,
                "The parent proxy asked for authentication again on a connection it had \
                 authenticated, and this request cannot be sent twice. Try again.",
                false,
            ),
        }
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

/// Like [`try_connect`], reporting a failure as an error page for the client.
pub(super) async fn connect_tcp(address: &str, limit: Duration) -> Result<TcpStream, Failure> {
    try_connect(address, limit)
        .await
        .map_err(|error| match error {
            ConnectError::Timeout => Failure::ConnectTimeout(address.to_owned()),
            ConnectError::Io(source) => Failure::Connect {
                address: address.to_owned(),
                source,
            },
        })
}
