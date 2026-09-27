//! Forwarding plain HTTP requests, to the origin server or to a parent proxy.

use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;

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
use super::failure::Failure;
use super::headers::{apply_rules, strip_hop_by_hop};
use super::parent::{Admission, Outcome, ParentAuth, reusable};
use super::pool::{Lease, Pool};
use super::server::{Context, Live};
use super::upstream::{Hop, Opened};
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

/// What one request works with: the settings as they were when it began, which
/// a reload does not change under it, and the pool it borrows connections from.
/// It reads as the settings do, so `scope.timeouts` is the timeouts.
struct Scope<'a> {
    live: &'a Live,
    pool: &'a Arc<Pool>,
    /// The generation of the pool the settings belong to.
    epoch: u64,
}

impl Deref for Scope<'_> {
    type Target = Live;

    fn deref(&self) -> &Live {
        self.live
    }
}

async fn forward(request: Request<Incoming>, context: &Context) -> Result<Response<Body>, Failure> {
    // In this order: a connection may be labeled with an older generation than
    // its settings, and is then simply not kept, but never with a newer one.
    let epoch = context.pool.epoch();
    let live = context.live();
    let context = &Scope {
        live: &live,
        pool: &context.pool,
        epoch,
    };
    let (mut parts, body) = request.into_parts();
    let target = Target::from_uri(&parts.uri)?;

    strip_hop_by_hop(&mut parts.headers);
    apply_rules(&mut parts.headers, &context.request_headers);
    parts.headers.insert(HOST, target.host_header.clone());

    let hops = context
        .upstreams
        .hops(&target.pac_url(), &target.host)
        .await?;
    let mut lease = acquire(context, hops, &target).await?;
    // A proxy is addressed with the full URL, so it knows the destination.
    let uri = match lease.hop {
        Hop::Direct => target.origin_form.clone(),
        Hop::Parent(_) => target.absolute.clone(),
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

    let mut request = Request::new(body);
    *request.method_mut() = parts.method.clone();
    *request.uri_mut() = uri;
    *request.headers_mut() = parts.headers;
    *request.version_mut() = Version::HTTP_11;
    // Carries the original capitalization of the header names (see the server
    // and client builders), which some proxies and firewalls are picky about.
    *request.extensions_mut() = parts.extensions;

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
            None => return Err(Failure::ResponseTimeout(lease.hop.who())),
            Some(Ok(response)) if demands_authentication(&response, &lease.hop, context) => {
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
                let hop = lease.hop.clone();
                lease = connect(context, &hop, &target).await?;
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
        let hop = lease.hop.clone();
        lease = connect(context, &hop, &target).await?;
    };

    if lease.hop.is_parent()
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
        lease.attach(context.pool, body),
    ))
}

/// Whether the parent is asking for authentication, and has been given the
/// means to provide it.
fn demands_authentication(response: &Response<Incoming>, hop: &Hop, context: &Scope<'_>) -> bool {
    hop.is_parent()
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
    context: &Scope<'_>,
    lease: &mut Lease,
    request: &mut Request<Body>,
    head: Option<&Head>,
    target: &Target,
    lapsed: bool,
) -> Result<Authenticated<'a>, Failure> {
    let admission = auth.admit().await?;
    let limit = context.timeouts.response;
    let Hop::Parent(parent) = &lease.hop else {
        return Err(Failure::Parent(
            "a connection to an origin server was asked to authenticate as a parent",
        ));
    };
    let pending = auth.begin(&parent.host);
    let real = head.filter(|head| lapsed || head.method != Method::HEAD);
    let is_real = real.is_some();
    let carrier = || match real {
        Some(head) => head.request(),
        None => probe(target, &context.request_headers),
    };

    lease.needs_auth = false;
    match auth
        .negotiate(&mut lease.sender, carrier, pending, limit)
        .await?
    {
        Outcome::Proof { header, made } => {
            request.headers_mut().insert(PROXY_AUTHORIZATION, header);
            Ok(Authenticated::Proof(admission.made_from(made)))
        }
        Outcome::Answered(response) if is_real => Ok(Authenticated::Answered(response)),
        Outcome::Answered(response) => {
            // The probe got an answer, which is not for the client. If it
            // cannot be read to the end, the connection is of no further use.
            let (_, body) = response.into_parts();
            if !reusable(body, &mut lease.sender, limit).await {
                let hop = lease.hop.clone();
                *lease = connect(context, &hop, target).await?;
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

/// Opens a connection through the first of `hops` that answers: a pooled one if
/// there is one for a hop, else a new one.
async fn acquire(context: &Scope<'_>, hops: Vec<Hop>, target: &Target) -> Result<Lease, Failure> {
    let opened = context
        .upstreams
        .open(
            hops,
            &target.address,
            context.timeouts.connect,
            context.auth.as_deref(),
            Some(context.pool),
        )
        .await?;
    match opened {
        Opened::Reused(hop, sender) => Ok(Lease {
            sender,
            key: hop.pool_key(&target.address),
            hop,
            reused: true,
            needs_auth: false,
            epoch: context.epoch,
        }),
        Opened::New(hop, stream) => new_lease(context, hop, stream, target).await,
    }
}

/// Opens a new connection through `hop`.
async fn connect(context: &Scope<'_>, hop: &Hop, target: &Target) -> Result<Lease, Failure> {
    // No point opening a connection that could not be authenticated.
    if let (Hop::Parent(_), Some(auth)) = (hop, &context.auth) {
        auth.check()?;
    }
    let stream = context
        .upstreams
        .connect_hop(hop, &target.address, context.timeouts.connect)
        .await?;
    new_lease(context, hop.clone(), stream, target).await
}

async fn new_lease(
    context: &Scope<'_>,
    hop: Hop,
    stream: TcpStream,
    target: &Target,
) -> Result<Lease, Failure> {
    Ok(Lease {
        sender: handshake(stream).await?,
        key: hop.pool_key(&target.address),
        needs_auth: hop.is_parent() && context.auth.is_some(),
        hop,
        reused: false,
        epoch: context.epoch,
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
    /// The URL as a PAC script gets it: the host in lower case, and no user
    /// information.
    fn pac_url(&self) -> String {
        let authority = self
            .absolute
            .authority()
            .map_or("", |authority| authority.as_str())
            .to_ascii_lowercase();
        let path_and_query = self
            .absolute
            .path_and_query()
            .map_or("/", |path_and_query| path_and_query.as_str());
        format!("http://{authority}{path_and_query}")
    }

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
