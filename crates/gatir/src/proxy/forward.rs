//! Forwarding plain HTTP requests directly to the origin server.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{HOST, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::body::{Body, error_response};
use super::headers::strip_hop_by_hop;
use super::server::Context;

pub(super) async fn handle(
    request: Request<Incoming>,
    context: &Context,
    peer: SocketAddr,
) -> Response<Body> {
    let method = request.method().clone();
    let host = request
        .uri()
        .host()
        .map_or_else(|| "-".to_owned(), str::to_owned);

    let response = match forward(request, context).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    };
    tracing::debug!(
        peer = %peer.ip(),
        %method,
        %host,
        status = response.status().as_u16(),
        "request handled"
    );
    response
}

async fn forward(request: Request<Incoming>, context: &Context) -> Result<Response<Body>, Failure> {
    if request.method() == Method::CONNECT {
        return Err(Failure::NotImplemented("CONNECT is not supported yet"));
    }

    let (mut parts, body) = request.into_parts();
    let target = Target::from_uri(&parts.uri)?;

    strip_hop_by_hop(&mut parts.headers);
    parts.headers.insert(HOST, target.host_header.clone());

    let mut upstream = Request::new(body);
    *upstream.method_mut() = parts.method;
    *upstream.uri_mut() = target.origin_form;
    *upstream.headers_mut() = parts.headers;
    *upstream.version_mut() = Version::HTTP_11;

    let mut sender = connect(&target.address, context.timeouts.connect).await?;
    let response = sender
        .send_request(upstream)
        .await
        .map_err(Failure::Upstream)?;

    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    parts.version = Version::HTTP_11;
    Ok(Response::from_parts(parts, body.boxed_unsync()))
}

/// Opens a connection to `address` and starts the HTTP/1 client driver on it.
async fn connect(address: &str, limit: Duration) -> Result<http1::SendRequest<Incoming>, Failure> {
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

    let (sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(Failure::Upstream)?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(%err, "upstream connection ended with error");
        }
    });
    Ok(sender)
}

/// Where a request is going, taken from its absolute-form request target.
struct Target {
    /// `host:port`, ready for `TcpStream::connect`.
    address: String,
    host_header: HeaderValue,
    origin_form: Uri,
}

impl Target {
    fn from_uri(uri: &Uri) -> Result<Self, Failure> {
        match uri.scheme_str() {
            Some("http") => {}
            Some(_) => {
                return Err(Failure::BadRequest(
                    "only http:// URLs can be forwarded; use CONNECT for https",
                ));
            }
            None => {
                return Err(Failure::BadRequest(
                    "gatir is a proxy: send requests in absolute form (http://host/path)",
                ));
            }
        }
        let authority = uri
            .authority()
            .ok_or(Failure::BadRequest("the request URL has no host"))?;

        let host = authority.host();
        let port = authority.port_u16().unwrap_or(80);
        let host_header = match authority.port_u16() {
            Some(explicit) => format!("{host}:{explicit}"),
            None => host.to_owned(),
        };
        let host_header = HeaderValue::from_str(&host_header)
            .map_err(|_| Failure::BadRequest("the request URL has an invalid host"))?;

        let path_and_query = uri.path_and_query().map_or("/", |pq| pq.as_str());
        let origin_form = path_and_query
            .parse::<Uri>()
            .map_err(|_| Failure::BadRequest("the request URL has an invalid path"))?;

        Ok(Self {
            address: format!("{host}:{port}"),
            host_header,
            origin_form,
        })
    }
}

enum Failure {
    BadRequest(&'static str),
    NotImplemented(&'static str),
    ConnectTimeout(String),
    Connect { address: String, source: io::Error },
    Upstream(hyper::Error),
}

impl Failure {
    fn into_response(self) -> Response<Body> {
        match self {
            Self::BadRequest(message) => error_response(StatusCode::BAD_REQUEST, message, true),
            Self::NotImplemented(message) => {
                error_response(StatusCode::NOT_IMPLEMENTED, message, false)
            }
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
