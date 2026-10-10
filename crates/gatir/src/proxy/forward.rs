//! Forwarding plain HTTP requests, to the origin server or to a parent proxy.

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Incoming};
use hyper::header::{AUTHORIZATION, HOST, HeaderMap, HeaderValue, PROXY_AUTHORIZATION};
use hyper::http::Extensions;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use tokio::net::TcpStream;

use super::body::{Body, Sent, full, response_within, watch};
use super::failure::{Failure, ParentAttempt, ended_without_answer};
use super::headers::{apply_rules, strip_hop_by_hop};
use super::parent::{Admission, Outcome, ParentAuth, negotiate_origin, reusable};
use super::pool::Lease;
use super::server::{Context, Live};
use super::upstream::{Hop, Opened, handshake};
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
    // The settings as they are now, and the pool that goes with them: what
    // follows is done under them, even if a reload happens meanwhile.
    let live = context.live();
    let context = &*live;
    let (mut parts, body) = request.into_parts();
    let target = Target::from_uri(&parts.uri)?;

    strip_hop_by_hop(&mut parts.headers);
    apply_rules(&mut parts.headers, &context.request_headers);
    parts.headers.insert(HOST, target.host_header.clone());

    let mut hops = context
        .upstreams
        .hops(&target.pac_url(), &target.host)
        .await?;
    // The parents that accepted a connection and ended it without answering.
    let mut tried = Vec::new();
    let mut lease = acquire(context, hops.clone(), &target).await?;

    // A request that never had a body can be built again: to send it after a
    // failed attempt, or to open the authentication with.
    let head = body.is_end_stream().then(|| Head {
        method: parts.method.clone(),
        absolute: target.absolute.clone(),
        origin_form: target.origin_form.clone(),
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
    *request.uri_mut() = target.uri_for(&lease.hop);
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
            .await
            {
                Ok(Authenticated::Answered(response)) => break response,
                Ok(Authenticated::Proof(proof)) => admission = Some(proof),
                Ok(Authenticated::Ready) => {}
                // Nothing of the request was sent but its head, or a probe, so
                // it is the same for the next parent.
                Err(Failure::NoAnswer(error)) if lease.hop.is_parent() => {
                    admission = None;
                    lease =
                        fail_over(context, &lease, &error, &mut hops, &mut tried, &target).await?;
                    *request.uri_mut() = target.uri_for(&lease.hop);
                    continue;
                }
                Err(failure) => return Err(failure),
            }
        }

        let attempt = response_within(limit, &mut sent, lease.sender.try_send_request(request));
        let mut failed = match attempt.await {
            None => return Err(Failure::ResponseTimeout(lease.hop.who())),
            Some(Ok(response))
                if demands_authentication(&response, &lease.hop, context, &target.host) =>
            {
                if !lease.reused {
                    context.upstreams.worked(&lease.hop);
                }
                if let Some(proof) = admission.take() {
                    return Err(match &lease.hop {
                        Hop::Parent(_) => proof.refused(),
                        Hop::Direct => proof.refused_by_origin(&target.host),
                    });
                }
                // No proof went out on this connection: it had been
                // authenticated, and is not any more.
                let Some(head) = head.as_ref().filter(|_| !lapsed) else {
                    return Err(Failure::AuthenticationLapsed);
                };
                tracing::debug!("a connection lost its authentication, retrying on a new one");
                lapsed = true;
                let hop = lease.hop.clone();
                request = head.request(&hop);
                sent = Sent::already();
                lease = connect(context, &hop, &target).await?;
                continue;
            }
            Some(Ok(response)) => {
                if !lease.reused {
                    context.upstreams.worked(&lease.hop);
                }
                if let Some(proof) = admission.take() {
                    proof.accepted();
                }
                break response;
            }
            Some(Err(failed)) => failed,
        };
        let returned = failed.take_message();
        let error = failed.into_error();
        // A new connection to a parent that wants no authentication, and that
        // ended without a word: the next parent may do. (When there are
        // credentials, the parent has answered by now: see `authenticate`.)
        if !lease.reused
            && lease.hop.is_parent()
            && context.auth.is_none()
            && ended_without_answer(&error)
        {
            let again = match (returned, head.as_ref()) {
                (Some(returned), _) => Some(returned),
                (None, Some(head)) => {
                    sent = Sent::already();
                    Some(head.request(&lease.hop))
                }
                // The body is gone, partly or all of it: it cannot be sent again.
                (None, None) => None,
            };
            let Some(again) = again else {
                context.upstreams.no_answer(&lease.hop, &error);
                return Err(Failure::NoAnswer(error));
            };
            request = again;
            lease = fail_over(context, &lease, &error, &mut hops, &mut tried, &target).await?;
            *request.uri_mut() = target.uri_for(&lease.hop);
            continue;
        }
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
                replay.request(&lease.hop)
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
        lease.attach(&context.pool, body),
    ))
}

/// Whether the next hop is asking for authentication, and has been given the
/// means to provide it: the parent's `407`, or, for a direct connection to a
/// host named in `credentials.origin_hosts`, its own `401`.
fn demands_authentication(
    response: &Response<Incoming>,
    hop: &Hop,
    context: &Live,
    host: &str,
) -> bool {
    match hop {
        Hop::Parent(_) => {
            context.auth.is_some() && response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED
        }
        Hop::Direct => {
            context
                .auth
                .as_deref()
                .is_some_and(|auth| auth.ntlm_for_origin(host).is_some())
                && response.status() == StatusCode::UNAUTHORIZED
        }
    }
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

/// Runs the first half of the exchange on a new connection: to the parent, or,
/// for a host named in `credentials.origin_hosts`, straight to the origin.
///
/// A request without a body opens the exchange itself, so when the other side
/// asks for nothing its answer is the real one. Otherwise a probe does: a
/// `GET`, never the method of the request, so that nothing is done twice if it
/// answers it. That also goes for `HEAD`, which some proxies do not accept
/// there, unless a first attempt has already gone wrong.
async fn authenticate<'a>(
    auth: &'a ParentAuth,
    context: &Live,
    lease: &mut Lease,
    request: &mut Request<Body>,
    head: Option<&Head>,
    target: &Target,
    lapsed: bool,
) -> Result<Authenticated<'a>, Failure> {
    let admission = auth.admit().await?;
    let limit = context.timeouts.response;
    let real = head.filter(|head| lapsed || head.method != Method::HEAD);
    let is_real = real.is_some();
    let through = lease.hop.clone();
    let carrier = || match real {
        Some(head) => head.request(&through),
        None => probe(target, &context.request_headers),
    };

    lease.needs_auth = false;
    let (outcome, proof_goes_in) = match &lease.hop {
        Hop::Parent(parent) => {
            let hop = lease.hop.clone();
            let outcome = auth
                .negotiate(&mut lease.sender, carrier, &parent.host, limit, || {
                    Box::pin(async {
                        let stream = context
                            .upstreams
                            .connect_hop(&hop, &target.address, context.timeouts.connect)
                            .await?;
                        handshake(stream).await
                    })
                })
                .await?;
            (outcome, PROXY_AUTHORIZATION)
        }
        Hop::Direct => {
            let ntlm = auth.ntlm_for_origin(&target.host).expect(
                "a direct connection needs authentication only when the host is one of \
                 credentials.origin_hosts",
            );
            let outcome = negotiate_origin(ntlm, &mut lease.sender, carrier, limit).await?;
            (outcome, AUTHORIZATION)
        }
    };
    // Whatever it said, it said something.
    context.upstreams.worked(&lease.hop);
    match outcome {
        Outcome::Proof { header, made } => {
            request.headers_mut().insert(proof_goes_in, header);
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

/// A parent accepted the connection and ended it before answering the first
/// request on it. It is left for last for a while, and the connection is
/// opened through the next of the `hops` that is left. If there is none, the
/// client is told about every parent that was tried.
async fn fail_over(
    context: &Live,
    from: &Lease,
    error: &hyper::Error,
    hops: &mut Vec<Hop>,
    tried: &mut Vec<ParentAttempt>,
    target: &Target,
) -> Result<Lease, Failure> {
    tried.push(context.upstreams.no_answer(&from.hop, error));
    hops.retain(|hop| *hop != from.hop);
    if hops.is_empty() {
        return Err(Failure::ParentsUnavailable(std::mem::take(tried)));
    }
    acquire(context, hops.clone(), target)
        .await
        .map_err(|failure| failure.after(std::mem::take(tried)))
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
async fn acquire(context: &Live, hops: Vec<Hop>, target: &Target) -> Result<Lease, Failure> {
    let opened = context
        .upstreams
        .open(
            hops,
            &target.address,
            context.timeouts.connect,
            context.auth.as_deref(),
            Some(&context.pool),
        )
        .await?;
    match opened {
        Opened::Reused(hop, sender) => Ok(Lease {
            sender,
            key: hop.pool_key(&target.address),
            hop,
            reused: true,
            needs_auth: false,
        }),
        Opened::New(hop, stream) => new_lease(context, hop, stream, target).await,
    }
}

/// Opens a new connection through `hop`.
async fn connect(context: &Live, hop: &Hop, target: &Target) -> Result<Lease, Failure> {
    // No point opening a connection that could not be authenticated.
    if let Some(auth) = &context.auth
        && needs_auth(hop, auth, &target.host)
    {
        auth.check()?;
    }
    let stream = context
        .upstreams
        .connect_hop(hop, &target.address, context.timeouts.connect)
        .await?;
    new_lease(context, hop.clone(), stream, target).await
}

/// Whether a new connection through `hop` needs authenticating before its
/// first real request: always for a parent, once credentials are configured;
/// for a direct one, only when the destination is named in
/// `credentials.origin_hosts`.
fn needs_auth(hop: &Hop, auth: &ParentAuth, host: &str) -> bool {
    match hop {
        Hop::Parent(_) => true,
        Hop::Direct => auth.ntlm_for_origin(host).is_some(),
    }
}

async fn new_lease(
    context: &Live,
    hop: Hop,
    stream: TcpStream,
    target: &Target,
) -> Result<Lease, Failure> {
    Ok(Lease {
        sender: handshake(stream).await?,
        key: hop.pool_key(&target.address),
        needs_auth: context
            .auth
            .as_deref()
            .is_some_and(|auth| needs_auth(&hop, auth, &target.host)),
        hop,
        reused: false,
    })
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
    /// The two ways the target is written: to a proxy and to a server.
    absolute: Uri,
    origin_form: Uri,
    headers: HeaderMap,
    extensions: Extensions,
}

impl Head {
    /// The request as it is sent through `hop`.
    fn request(&self, hop: &Hop) -> Request<Body> {
        let mut request = Request::new(full(Bytes::new()));
        *request.method_mut() = self.method.clone();
        *request.uri_mut() = match hop {
            Hop::Direct => self.origin_form.clone(),
            Hop::Parent(_) => self.absolute.clone(),
        };
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
    /// How the target is written in a request sent through `hop`. A proxy is
    /// addressed with the full URL, so it knows the destination.
    fn uri_for(&self, hop: &Hop) -> Uri {
        match hop {
            Hop::Direct => self.origin_form.clone(),
            Hop::Parent(_) => self.absolute.clone(),
        }
    }

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
