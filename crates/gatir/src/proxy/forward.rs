//! Forwarding plain HTTP requests, to the origin server or to a parent proxy.

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Incoming};
use hyper::client::conn::http1;
use hyper::header::{HOST, HeaderMap, HeaderValue};
use hyper::http::Extensions;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use super::body::{Body, full};
use super::failure::{Failure, connect_tcp};
use super::headers::{apply_rules, strip_hop_by_hop};
use super::pool::{Lease, PoolKey};
use super::server::Context;
use super::upstream::Route;

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
    let (mut parts, body) = request.into_parts();
    let target = Target::from_uri(&parts.uri)?;

    strip_hop_by_hop(&mut parts.headers);
    apply_rules(&mut parts.headers, &context.request_headers);
    parts.headers.insert(HOST, target.host_header.clone());

    let route = context.upstreams.route(&target.host);
    // A proxy is addressed with the full URL, so it knows the destination.
    let uri = match route {
        Route::Direct => target.origin_form.clone(),
        Route::Parent => target.absolute.clone(),
    };

    // A request that never had a body and does not change anything can safely
    // be sent again if a pooled connection turns out to be dead.
    let replay = (body.is_end_stream() && is_idempotent(&parts.method)).then(|| Replay {
        method: parts.method.clone(),
        uri: uri.clone(),
        headers: parts.headers.clone(),
        extensions: parts.extensions.clone(),
    });

    let mut request = Request::new(body.boxed_unsync());
    *request.method_mut() = parts.method;
    *request.uri_mut() = uri;
    *request.headers_mut() = parts.headers;
    *request.version_mut() = Version::HTTP_11;
    // Carries the original capitalization of the header names (see the server
    // and client builders), which some proxies and firewalls are picky about.
    *request.extensions_mut() = parts.extensions;

    let mut lease = acquire(context, route, &target).await?;
    let response = loop {
        let mut failed = match lease.sender.try_send_request(request).await {
            Ok(response) => break response,
            Err(failed) => failed,
        };
        let returned = failed.take_message();
        let error = failed.into_error();
        // Only a pooled connection can have gone stale unnoticed. The request
        // may be sent again if hyper never sent it, or if it is safe to repeat.
        let repeatable = returned.is_some() || (replay.is_some() && is_stale(&error));
        if !lease.reused || !repeatable {
            return Err(Failure::Upstream(error));
        }
        tracing::debug!(%error, "pooled connection was stale, retrying on a new one");
        request = match (returned, &replay) {
            (Some(returned), _) => returned,
            (None, Some(replay)) => replay.request(),
            (None, None) => return Err(Failure::Upstream(error)),
        };
        lease = connect(context, route, &target).await?;
    };

    if route == Route::Parent && response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        tracing::warn!(
            "the parent proxy answered 407: it wants authentication, which is not supported yet"
        );
    }

    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    parts.version = Version::HTTP_11;
    Ok(Response::from_parts(
        parts,
        lease.attach(&context.pool, body),
    ))
}

/// A pooled connection if there is one for the destination, else a new one.
async fn acquire(context: &Context, route: Route, target: &Target) -> Result<Lease, Failure> {
    let key = match route {
        Route::Direct => PoolKey::Origin(target.address.clone()),
        Route::Parent => PoolKey::Parent(context.upstreams.current_parent()),
    };
    match context.pool.take(&key).await {
        Some(sender) => Ok(Lease {
            sender,
            key,
            reused: true,
        }),
        None => connect(context, route, target).await,
    }
}

/// Opens a new connection to the destination, or to a parent proxy.
async fn connect(context: &Context, route: Route, target: &Target) -> Result<Lease, Failure> {
    let limit = context.timeouts.connect;
    let (stream, key) = match route {
        Route::Direct => (
            connect_tcp(&target.address, limit).await?,
            PoolKey::Origin(target.address.clone()),
        ),
        Route::Parent => {
            let (index, stream) = context.upstreams.connect_parent(limit).await?;
            (stream, PoolKey::Parent(index))
        }
    };
    Ok(Lease {
        sender: handshake(stream).await?,
        key,
        reused: false,
    })
}

/// Starts the HTTP/1 client driver on a connected stream.
async fn handshake(stream: TcpStream) -> Result<http1::SendRequest<Body>, Failure> {
    let (sender, connection) = http1::Builder::new()
        .preserve_header_case(true)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(Failure::Upstream)?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(%err, "upstream connection ended with error");
        }
    });
    Ok(sender)
}

/// Methods that RFC 9110 defines as idempotent: repeating them is harmless.
fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
    )
}

/// Whether an error means the server had already closed the connection.
fn is_stale(error: &hyper::Error) -> bool {
    error.is_canceled() || error.is_incomplete_message() || error.is_closed()
}

/// What is needed to build the same body-less request again.
struct Replay {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    extensions: Extensions,
}

impl Replay {
    fn request(&self) -> Request<Body> {
        let mut request = Request::new(full(Bytes::new()));
        *request.method_mut() = self.method.clone();
        *request.uri_mut() = self.uri.clone();
        *request.headers_mut() = self.headers.clone();
        *request.version_mut() = Version::HTTP_11;
        *request.extensions_mut() = self.extensions.clone();
        request
    }
}

/// Where a request is going, taken from its absolute-form request target.
struct Target {
    /// The host, as written in the URL (IPv6 literals keep their brackets).
    host: String,
    /// `host:port`, ready for `TcpStream::connect`.
    address: String,
    host_header: HeaderValue,
    origin_form: Uri,
    /// The URL without any user information.
    absolute: Uri,
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
        let host_and_port = match authority.port_u16() {
            Some(explicit) => format!("{host}:{explicit}"),
            None => host.to_owned(),
        };
        let host_header = HeaderValue::from_str(&host_and_port)
            .map_err(|_| Failure::BadRequest("the request URL has an invalid host"))?;

        let path_and_query = uri.path_and_query().map_or("/", |pq| pq.as_str());
        let origin_form = path_and_query
            .parse::<Uri>()
            .map_err(|_| Failure::BadRequest("the request URL has an invalid path"))?;
        let absolute = format!("http://{host_and_port}{path_and_query}")
            .parse::<Uri>()
            .map_err(|_| Failure::BadRequest("the request URL is invalid"))?;

        Ok(Self {
            host: host.to_owned(),
            address: format!("{host}:{port}"),
            host_header,
            origin_form,
            absolute,
        })
    }
}
