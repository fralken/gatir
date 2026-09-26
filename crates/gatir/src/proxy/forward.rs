//! Forwarding plain HTTP requests, to the origin server or to a parent proxy.

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Incoming};
use hyper::client::conn::http1;
use hyper::header::{HOST, HeaderMap, HeaderValue, PROXY_AUTHORIZATION};
use hyper::http::Extensions;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use super::body::{Body, Sent, full, response_within, watch};
use super::failure::{Failure, connect_tcp};
use super::headers::{apply_rules, strip_hop_by_hop};
use super::parent_auth::{Admission, Outcome, ParentAuth, reusable};
use super::pool::{Lease, PoolKey};
use super::server::Context;
use super::upstream::Route;
use crate::config::HeaderRule;

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

    // A request that never had a body can be built again: to send it after a
    // failed attempt, or to open the authentication with.
    let head = body.is_end_stream().then(|| Head {
        method: parts.method.clone(),
        uri: uri.clone(),
        headers: parts.headers.clone(),
        extensions: parts.extensions.clone(),
    });
    // If a pooled connection turns out to be dead, it may be sent again only
    // when that cannot change anything twice.
    let replay = head.as_ref().filter(|_| is_idempotent(&parts.method));

    // The wait for a response is timed from the moment the request is sent.
    let (body, mut sent) = watch(body.boxed_unsync());
    let limit = context.timeouts.response;
    let who = match route {
        Route::Direct => "the upstream server",
        Route::Parent => "the parent proxy",
    };

    let mut request = Request::new(body);
    *request.method_mut() = parts.method.clone();
    *request.uri_mut() = uri;
    *request.headers_mut() = parts.headers;
    *request.version_mut() = Version::HTTP_11;
    // Carries the original capitalization of the header names (see the server
    // and client builders), which some proxies and firewalls are picky about.
    *request.extensions_mut() = parts.extensions;

    let mut lease = acquire(context, route, &target).await?;
    // Set once a proof has been sent on `lease`, until the parent has said
    // whether it accepts it.
    let mut admission: Option<Admission<'_>> = None;
    // Whether the request was already repeated because a connection had lost
    // its authentication. Once is enough.
    let mut lapsed = false;

    let response = loop {
        if lease.needs_auth {
            let auth = context
                .auth
                .as_ref()
                .expect("a connection needs authentication only when there are credentials");
            match authenticate(
                auth,
                context,
                &mut lease,
                &mut request,
                head.as_ref(),
                &target,
                lapsed,
            )
            .await?
            {
                Authenticated::Answered(response) => break response,
                Authenticated::Proof(proof) => admission = Some(proof),
                Authenticated::Ready => {}
            }
        }

        let attempt = response_within(limit, &mut sent, lease.sender.try_send_request(request));
        let mut failed = match attempt.await {
            None => return Err(Failure::ResponseTimeout(who)),
            Some(Ok(response)) if demands_authentication(&response, route, context) => {
                if let Some(proof) = admission.take() {
                    return Err(proof.refused());
                }
                // No proof went out on this connection: it had been
                // authenticated, and is not any more.
                let Some(head) = head.as_ref().filter(|_| !lapsed) else {
                    return Err(Failure::AuthenticationLapsed);
                };
                tracing::debug!("a connection lost its authentication, retrying on a new one");
                lapsed = true;
                request = head.request();
                sent = Sent::already();
                lease = connect(context, route, &target).await?;
                continue;
            }
            Some(Ok(response)) => {
                if let Some(proof) = admission.take() {
                    proof.accepted();
                }
                break response;
            }
            Some(Err(failed)) => failed,
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
        request = match (returned, replay) {
            (Some(returned), _) => returned,
            (None, Some(replay)) => {
                sent = Sent::already();
                replay.request()
            }
            (None, None) => return Err(Failure::Upstream(error)),
        };
        lease = connect(context, route, &target).await?;
    };

    if route == Route::Parent
        && context.auth.is_none()
        && response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED
    {
        tracing::warn!(
            "the parent proxy answered 407: it wants authentication, but no credentials are configured"
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

/// Whether the parent is asking for authentication, and has been given the
/// means to provide it.
fn demands_authentication(response: &Response<Incoming>, route: Route, context: &Context) -> bool {
    route == Route::Parent
        && context.auth.is_some()
        && response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED
}

/// What came of authenticating a new connection to a parent.
enum Authenticated<'a> {
    /// The parent asked for nothing, and this is its answer to the request.
    Answered(Response<Incoming>),
    /// The request now carries a proof. The parent has yet to accept it.
    Proof(Admission<'a>),
    /// The parent asked for nothing: the connection is ready as it is.
    Ready,
}

/// Runs the first half of the NTLM exchange on a new connection to a parent.
///
/// A request without a body opens the exchange itself, so when the parent asks
/// for nothing its answer is the real one. Otherwise a probe does: a `GET`,
/// never the method of the request, so that nothing is done twice if the parent
/// answers it. That also goes for `HEAD`, which some proxies do not accept
/// there, unless a first attempt has already gone wrong.
async fn authenticate<'a>(
    auth: &'a ParentAuth,
    context: &Context,
    lease: &mut Lease,
    request: &mut Request<Body>,
    head: Option<&Head>,
    target: &Target,
    lapsed: bool,
) -> Result<Authenticated<'a>, Failure> {
    let admission = auth.admit().await?;
    let carrier = head
        .filter(|head| lapsed || head.method != Method::HEAD)
        .map(Head::request);
    let is_real = carrier.is_some();
    let first = carrier.unwrap_or_else(|| probe(target, &context.request_headers));

    let limit = context.timeouts.response;
    lease.needs_auth = false;
    match auth.negotiate(&mut lease.sender, first, limit).await? {
        Outcome::Proof(proof) => {
            request.headers_mut().insert(PROXY_AUTHORIZATION, proof);
            Ok(Authenticated::Proof(admission))
        }
        Outcome::Answered(response) if is_real => Ok(Authenticated::Answered(response)),
        Outcome::Answered(response) => {
            // The probe got an answer, which is not for the client. If it
            // cannot be read to the end, the connection is of no further use.
            let (_, body) = response.into_parts();
            if !reusable(body, &mut lease.sender, limit).await {
                *lease = connect(context, Route::Parent, target).await?;
                lease.needs_auth = false;
            }
            Ok(Authenticated::Ready)
        }
    }
}

/// A request that only serves to open the authentication.
fn probe(target: &Target, rules: &[HeaderRule]) -> Request<Body> {
    let mut request = Request::new(full(Bytes::new()));
    *request.method_mut() = Method::GET;
    *request.uri_mut() = target.absolute.clone();
    *request.version_mut() = Version::HTTP_11;
    let headers = request.headers_mut();
    headers.insert(HOST, target.host_header.clone());
    apply_rules(headers, rules);
    request
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
            needs_auth: false,
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
            // No point opening a connection that could not be authenticated.
            if let Some(auth) = &context.auth {
                auth.check()?;
            }
            let (index, stream) = context.upstreams.connect_parent(limit).await?;
            (stream, PoolKey::Parent(index))
        }
    };
    Ok(Lease {
        sender: handshake(stream).await?,
        key,
        reused: false,
        needs_auth: route == Route::Parent && context.auth.is_some(),
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
struct Head {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    extensions: Extensions,
}

impl Head {
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
