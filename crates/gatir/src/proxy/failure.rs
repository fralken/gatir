//! Reasons a request cannot be served, and connecting to the next hop.

use std::fmt;
use std::io;
use std::time::Duration;

use hyper::header::{HeaderValue, RETRY_AFTER};
use hyper::{Response, StatusCode};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::body::{Body, error_response};
use super::parent::COOLDOWN;
use crate::auth::AuthError;
use crate::pac::PacError;

/// Why opening a TCP connection failed.
#[derive(Debug)]
pub(super) enum ConnectError {
    Timeout,
    Io(io::Error),
    /// The connection was accepted, then ended before a word was said: the
    /// text is how it ended.
    NoAnswer(String),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("timed out"),
            Self::Io(err) => err.fmt(f),
            Self::NoAnswer(how) => write!(f, "closed the connection without answering: {how}"),
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
    /// A parent proxy accepted the connection and ended it before answering
    /// the first request. Another parent may be tried; if none is left, or the
    /// request cannot be sent again, this is what the client is told.
    NoAnswer(hyper::Error),
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
    /// An origin server named in `credentials.origin_hosts` answered the NTLM
    /// proof with another `401`.
    OriginCredentialsRejected {
        user: String,
        host: String,
    },
    /// The parent refused the credentials recently, so nobody is trying yet.
    CoolingDown(Duration),
    /// The parent offers Negotiate and did not accept the Kerberos ticket.
    TicketRejected {
        service: String,
    },
    /// The parent answered the NTLM proof that the system made from the
    /// password of the logged-on user with another `407`.
    SessionRejected {
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
    /// What went wrong with the first exchange on a new connection to a parent:
    /// a parent that ended the connection without answering is not the same as
    /// one that answered something unintelligible.
    pub(super) fn first_answer(error: hyper::Error) -> Self {
        if ended_without_answer(&error) {
            Self::NoAnswer(error)
        } else {
            Self::Upstream(error)
        }
    }

    /// Puts the attempts that already failed in front of those of this failure,
    /// when it too is about parents that could not be used.
    pub(super) fn after(self, mut earlier: Vec<ParentAttempt>) -> Self {
        match self {
            Self::ParentsUnavailable(later) => {
                earlier.extend(later);
                Self::ParentsUnavailable(earlier)
            }
            other => other,
        }
    }

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
            Self::NoAnswer(err) => bad_gateway(format!(
                "The parent proxy accepted the connection and closed it without answering: {}",
                describe(err)
            )),
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
            Self::OriginCredentialsRejected { user, host } => bad_gateway(format!(
                "{host} rejected the credentials of {user}. Check credentials.origin_hosts, and \
                 the user name, domain and password. gatir will not try again for {} minutes, \
                 so that the account does not get locked.",
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
            Self::SessionRejected { service } => bad_gateway(format!(
                "The parent proxy did not accept the credentials of the logged-on user for \
                 {service} (NTLM). If the password was changed recently, sign out and in \
                 again. gatir will not try again for {} minutes, so that the account does not \
                 get locked.",
                COOLDOWN.as_secs() / 60
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

/// Whether the peer ended the connection before saying anything: closed it, or
/// reset it. That is what a proxy does that accepts connections it cannot
/// serve. Anything it did say, even an error, is not this, and a timeout is
/// not either.
pub(super) fn ended_without_answer(error: &hyper::Error) -> bool {
    if error.is_closed() || error.is_incomplete_message() || error.is_canceled() {
        return true;
    }
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(io) = cause.downcast_ref::<io::Error>() {
            return matches!(
                io.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            );
        }
        source = cause.source();
    }
    false
}

/// How an upstream connection ended, as the innermost cause says it.
pub(super) fn describe(error: &hyper::Error) -> String {
    let mut cause: &dyn std::error::Error = error;
    while let Some(inner) = cause.source() {
        cause = inner;
    }
    cause.to_string()
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
        // Only a parent proxy is ever blamed for this: a server reached
        // directly that does this was connected to, not asked for a hop.
        ConnectError::NoAnswer(how) => Failure::Connect {
            address: address.to_owned(),
            source: io::Error::new(io::ErrorKind::ConnectionReset, how),
        },
    }
}
