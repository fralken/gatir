//! Reasons a request cannot be served, and connecting to the next hop.

use std::fmt;
use std::io;
use std::time::Duration;

use hyper::{Response, StatusCode};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::body::{Body, error_response};

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
    Connect { address: String, source: io::Error },
    ParentsUnavailable(Vec<ParentAttempt>),
    Upstream(hyper::Error),
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
