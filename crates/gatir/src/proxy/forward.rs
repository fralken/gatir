//! Forwarding plain HTTP requests, to the origin server or to a parent proxy.

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Incoming};
use hyper::client::conn::TrySendError;
use hyper::header::{
    AUTHORIZATION, HOST, HeaderMap, HeaderValue, PROXY_AUTHORIZATION, WWW_AUTHENTICATE,
};
use hyper::http::Extensions;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use tokio::net::TcpStream;

use super::body::{Body, Sent, full, response_within, watch};
use super::failure::{Failure, ParentAttempt, ended_without_answer};
use super::headers::{apply_rules, strip_hop_by_hop};
use super::parent::{Admission, Opening, ParentAuth, reusable, warn_no_credentials};
use super::pool::Lease;
use super::server::{Context, Live};
use super::upstream::{Hop, Opened, handshake};
use crate::auth::ntlm;
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
    parts.headers.insert(HOST, target.host_header.clone());

    let hops = context
        .upstreams
        .hops(&target.pac_url(), &target.host)
        .await?;
    let lease = acquire(context, hops.clone(), &target).await?;

    // A request that never had a body can be built again: to send it after a
    // failed attempt, or to open the authentication with.
    let head = body.is_end_stream().then(|| Head {
        method: parts.method.clone(),
        headers: parts.headers.clone(),
        extensions: parts.extensions.clone(),
    });

    // The wait for a response is timed from the moment the request is sent.
    let (body, sent) = watch(body.boxed_unsync());
    let mut request = Request::new(body);
    *request.method_mut() = parts.method.clone();
    *request.version_mut() = Version::HTTP_11;
    // Carries the original capitalization of the header names (see the server
    // and client builders), which some proxies and firewalls are picky about.
    *request.extensions_mut() = parts.extensions;

    let mut forwarding = Forwarding {
        context,
        idempotent: is_idempotent(&parts.method),
        headers: parts.headers,
        target,
        head,
        hops,
        tried: Vec::new(),
        sent,
        admission: None,
        lapsed: false,
    };
    forwarding.address(&mut request, &lease.hop);
    let (response, lease) = forwarding.run(lease, request).await?;

    if lease.hop.is_parent()
        && context.auth.is_none()
        && response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED
    {
        warn_no_credentials();
    }

    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    parts.version = Version::HTTP_11;
    Ok(Response::from_parts(
        parts,
        lease.attach(&context.pool, body),
    ))
}

/// One request on its way: what is needed to send it, and to send it again
/// on another connection or through another hop when an attempt fails.
struct Forwarding<'a> {
    context: &'a Live,
    target: Target,
    /// The client's header fields, without the hop-by-hop ones.
    headers: HeaderMap,
    /// The request, if it has no body and can be built again.
    head: Option<Head>,
    /// Whether doing the request twice is harmless.
    idempotent: bool,
    /// The hops not yet given up on, in order.
    hops: Vec<Hop>,
    /// The parents that accepted a connection and ended it without answering.
    tried: Vec<ParentAttempt>,
    /// When the request went out, for the response timeout.
    sent: Sent,
    /// Set once a proof has been sent, until the other side has said whether
    /// it accepts it.
    admission: Option<Admission<'a>>,
    /// Whether the request was already sent again because a connection had
    /// lost its authentication. Once is enough.
    lapsed: bool,
}

impl<'a> Forwarding<'a> {
    /// Sends `request` on `lease`, and on new connections or through other
    /// hops as long as an attempt fails in a way that allows another. Returns
    /// the response, and the connection it came on.
    async fn run(
        &mut self,
        mut lease: Lease,
        mut request: Request<Body>,
    ) -> Result<(Response<Incoming>, Lease), Failure> {
        loop {
            if lease.needs_auth
                && let Some(response) = self.authenticate(&mut lease, &mut request).await?
            {
                return Ok((response, lease));
            }
            let limit = self.context.timeouts.response;
            let attempt = response_within(
                limit,
                &mut self.sent,
                lease.sender.try_send_request(request),
            );
            (lease, request) = match attempt.await {
                None => return Err(Failure::ResponseTimeout(lease.hop.who())),
                Some(Ok(response))
                    if demands_authentication(
                        &response,
                        &lease.hop,
                        self.context,
                        &self.target.host,
                    ) =>
                {
                    self.lost_authentication(&lease).await?
                }
                Some(Ok(response)) => {
                    if !lease.reused {
                        self.context.upstreams.worked(&lease.hop);
                    }
                    if let Some(proof) = self.admission.take() {
                        proof.accepted();
                    }
                    return Ok((response, lease));
                }
                Some(Err(failed)) => self.after_failure(lease, failed).await?,
            };
        }
    }

    /// Authenticates the new connection `lease`, moving on to the next parent
    /// if this one ends the connection without answering. Returns the response
    /// if the other side asked for nothing and the request itself opened the
    /// exchange.
    async fn authenticate(
        &mut self,
        lease: &mut Lease,
        request: &mut Request<Body>,
    ) -> Result<Option<Response<Incoming>>, Failure> {
        let context = self.context;
        let auth = context
            .auth
            .as_deref()
            .expect("a connection needs authentication only when there are credentials");
        loop {
            let replay = self.head.as_ref().filter(|_| self.idempotent);
            match authenticate(
                auth,
                context,
                lease,
                request,
                replay,
                &self.target,
                self.lapsed,
            )
            .await
            {
                Ok(Authenticated::Answered(response)) => return Ok(Some(response)),
                Ok(Authenticated::Proof(proof)) => {
                    self.admission = Some(proof);
                    return Ok(None);
                }
                Ok(Authenticated::Ready) => return Ok(None),
                // Only a probe went out, or a request that is safe to repeat,
                // so it is the same for the next parent.
                Err(Failure::NoAnswer(error)) if lease.hop.is_parent() => {
                    *lease = self.fail_over(lease, &error).await?;
                    self.address(request, &lease.hop);
                    if !lease.needs_auth {
                        return Ok(None);
                    }
                }
                Err(failure) => return Err(failure),
            }
        }
    }

    /// The other side asked for authentication on `lease`. After a proof, that
    /// is a refusal. On a connection that had been authenticated before, the
    /// request is sent again, once, on a new connection: the answer says that
    /// it was not served, so even a request that is not safe to repeat can go
    /// again, as long as it has no body.
    async fn lost_authentication(
        &mut self,
        lease: &Lease,
    ) -> Result<(Lease, Request<Body>), Failure> {
        if !lease.reused {
            self.context.upstreams.worked(&lease.hop);
        }
        if let Some(proof) = self.admission.take() {
            return Err(proof.refused());
        }
        let Some(head) = self.head.as_ref().filter(|_| !self.lapsed) else {
            return Err(Failure::AuthenticationLapsed(lease.hop.who()));
        };
        tracing::debug!("a connection lost its authentication, retrying on a new one");
        let request = head.request(&lease.hop, &self.target, &self.context.request_headers);
        self.lapsed = true;
        self.sent = Sent::already();
        let lease = connect(self.context, &lease.hop, &self.target).await?;
        Ok((lease, request))
    }

    /// The connection `lease` failed before an answer came. Two cases allow
    /// another attempt: a new connection to a parent that wants no
    /// authentication and ended without a word, which moves on to the next
    /// parent; and a pooled connection that had gone stale unnoticed, which is
    /// replaced by a new one through the same hop. (When there are
    /// credentials, a new connection to a parent has answered by now: see
    /// `authenticate`.)
    async fn after_failure(
        &mut self,
        lease: Lease,
        mut failed: TrySendError<Request<Body>>,
    ) -> Result<(Lease, Request<Body>), Failure> {
        let returned = failed.take_message();
        let error = failed.into_error();

        if !lease.reused
            && lease.hop.is_parent()
            && self.context.auth.is_none()
            && ended_without_answer(&error)
        {
            let Some(mut request) = self.resend(returned, &lease.hop) else {
                self.context.upstreams.no_answer(&lease.hop, &error);
                return Err(Failure::NoAnswer(error));
            };
            let next = self.fail_over(&lease, &error).await?;
            self.address(&mut request, &next.hop);
            return Ok((next, request));
        }

        if !lease.reused || (returned.is_none() && !is_stale(&error)) {
            return Err(Failure::Upstream(error));
        }
        let Some(request) = self.resend(returned, &lease.hop) else {
            return Err(Failure::Upstream(error));
        };
        tracing::debug!(%error, "pooled connection was stale, retrying on a new one");
        let lease = connect(self.context, &lease.hop, &self.target).await?;
        Ok((lease, request))
    }

    /// The request to send again through `hop` after a failed attempt: the one
    /// hyper gave back unsent, or else, if doing it twice is harmless, the
    /// same request built again. `None` if it cannot go again: the other side
    /// may have acted on it, or its body is gone.
    fn resend(&mut self, returned: Option<Request<Body>>, hop: &Hop) -> Option<Request<Body>> {
        if returned.is_some() {
            return returned;
        }
        let head = self.head.as_ref().filter(|_| self.idempotent)?;
        let request = head.request(hop, &self.target, &self.context.request_headers);
        self.sent = Sent::already();
        Some(request)
    }

    /// A parent accepted the connection `from` and ended it before answering.
    /// It is left for last for a while, and a connection is opened through the
    /// next hop that is left. If there is none, the client is told about every
    /// parent that was tried.
    async fn fail_over(&mut self, from: &Lease, error: &hyper::Error) -> Result<Lease, Failure> {
        self.admission = None;
        self.tried
            .push(self.context.upstreams.no_answer(&from.hop, error));
        self.hops.retain(|hop| *hop != from.hop);
        if self.hops.is_empty() {
            return Err(Failure::ParentsUnavailable(std::mem::take(&mut self.tried)));
        }
        acquire(self.context, self.hops.clone(), &self.target)
            .await
            .map_err(|failure| failure.after(std::mem::take(&mut self.tried)))
    }

    /// Writes `request` for `hop`: see [`address`].
    fn address(&self, request: &mut Request<Body>, hop: &Hop) {
        address(
            request,
            &self.headers,
            hop,
            &self.target,
            &self.context.request_headers,
        );
    }
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
                && ntlm::offered(response.headers().get_all(WWW_AUTHENTICATE))
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
/// `replay` is the request if it has no body and is safe to repeat. It then
/// opens the exchange itself, so when the other side asks for nothing its
/// answer is the real one. Any other request is preceded by a probe: a `GET`,
/// never the method of the request, so that nothing is done twice if the other
/// side answers the probe, or fails after passing it on. That also goes for
/// `HEAD`, which some proxies do not accept there, unless a first attempt has
/// already gone wrong.
async fn authenticate<'a>(
    auth: &'a ParentAuth,
    context: &Live,
    lease: &mut Lease,
    request: &mut Request<Body>,
    replay: Option<&Head>,
    target: &Target,
    lapsed: bool,
) -> Result<Authenticated<'a>, Failure> {
    let limit = context.timeouts.response;
    let real = replay.filter(|head| lapsed || head.method != Method::HEAD);
    let is_real = real.is_some();
    let through = lease.hop.clone();
    let carrier = || match real {
        Some(head) => head.request(&through, target, &context.request_headers),
        None => probe(target, &through, &context.request_headers),
    };

    lease.needs_auth = false;
    let (opening, proof_goes_in) = match &lease.hop {
        Hop::Parent(parent) => {
            let hop = lease.hop.clone();
            let reconnect = || {
                context
                    .upstreams
                    .reconnect(&hop, &target.address, context.timeouts.connect)
            };
            let opening = auth
                .open(&mut lease.sender, carrier, &parent.host, limit, reconnect)
                .await?;
            (opening, PROXY_AUTHORIZATION)
        }
        Hop::Direct => {
            let opening = auth
                .open_origin(
                    &target.address,
                    &target.host,
                    &mut lease.sender,
                    carrier,
                    limit,
                )
                .await?;
            (opening, AUTHORIZATION)
        }
    };
    // Whatever it said, it said something.
    context.upstreams.worked(&lease.hop);
    match opening {
        Opening::Proof { header, admission } => {
            request.headers_mut().insert(proof_goes_in, header);
            Ok(Authenticated::Proof(admission))
        }
        Opening::Answered(response) if is_real => Ok(Authenticated::Answered(response)),
        Opening::Answered(response) => {
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

/// A request that only serves to open the authentication with `hop`.
fn probe(target: &Target, hop: &Hop, rules: &[HeaderRule]) -> Request<Body> {
    let mut request = Request::new(full(Bytes::new()));
    *request.method_mut() = Method::GET;
    *request.version_mut() = Version::HTTP_11;
    let mut headers = HeaderMap::new();
    headers.insert(HOST, target.host_header.clone());
    address(&mut request, &headers, hop, target, rules);
    request
}

/// Writes `request` for `hop`: its target, and the `client` header fields plus,
/// through a parent only, the configured `[headers]`. Their values are secrets,
/// and a server reached directly may be reached over plain HTTP.
fn address(
    request: &mut Request<Body>,
    client: &HeaderMap,
    hop: &Hop,
    target: &Target,
    rules: &[HeaderRule],
) {
    *request.uri_mut() = target.uri_for(hop);
    let mut headers = client.clone();
    if hop.is_parent() {
        apply_rules(&mut headers, rules);
    }
    *request.headers_mut() = headers;
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
    /// The client's header fields, without the hop-by-hop ones.
    headers: HeaderMap,
    extensions: Extensions,
}

impl Head {
    /// The request to `target` as it is sent through `hop`.
    fn request(&self, hop: &Hop, target: &Target, rules: &[HeaderRule]) -> Request<Body> {
        let mut request = Request::new(full(Bytes::new()));
        *request.method_mut() = self.method.clone();
        *request.version_mut() = Version::HTTP_11;
        *request.extensions_mut() = self.extensions.clone();
        address(&mut request, &self.headers, hop, target, rules);
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
