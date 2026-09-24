//! Reasons a request cannot be served, and connecting to the next hop.

use std::io;
use std::time::Duration;

use hyper::{Response, StatusCode};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::body::{Body, error_response};

pub(super) enum Failure {
    BadRequest(&'static str),
    ConnectTimeout(String),
    Connect { address: String, source: io::Error },
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
            Self::Upstream(err) => error_response(
                StatusCode::BAD_GATEWAY,
                format!("Invalid response from the origin server: {err}"),
                false,
            ),
        }
    }
}

/// Opens a TCP connection to `address` (`host:port`), giving up after `limit`.
pub(super) async fn connect_tcp(address: &str, limit: Duration) -> Result<TcpStream, Failure> {
    let stream = match timeout(limit, TcpStream::connect(address)).await {
        Err(_) => return Err(Failure::ConnectTimeout(address.to_owned())),
        Ok(Err(source)) => {
            return Err(Failure::Connect {
                address: address.to_owned(),
                source,
            });
        }
        Ok(Ok(stream)) => stream,
    };
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(%err, "cannot set TCP_NODELAY on the upstream connection");
    }
    Ok(stream)
}
