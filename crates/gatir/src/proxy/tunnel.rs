//! CONNECT tunnels: an opaque byte pipe between the client and a destination.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HOST, HeaderMap, HeaderValue, PROXY_AUTHORIZATION};
use hyper::http::Extensions;
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::body::{Body, answer_within, full};
use super::failure::Failure;
use super::headers::{apply_rules, strip_hop_by_hop};
use super::parent::Outcome;
use super::server::{Context, Live};
use super::upstream::{Hop, handshake};
use crate::config::HostPort;

pub(super) async fn handle(
    request: Request<Incoming>,
    context: &Context,
    peer: SocketAddr,
) -> Response<Body> {
    let destination = request.uri().authority().map(ToString::to_string);
    let response = match open(request, context, peer).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    };
    tracing::debug!(
        peer = %peer.ip(),
        destination = destination.as_deref().unwrap_or("-"),
        status = response.status().as_u16(),
        "CONNECT handled"
    );
    response
}

/// Connects to the destination first (directly, or by asking a parent proxy to),
/// so a failure can still be reported to the client as an HTTP error; only then
/// is the tunnel promised with a 200.
async fn open(
    mut request: Request<Incoming>,
    context: &Context,
    peer: SocketAddr,
) -> Result<Response<Body>, Failure> {
    let authority = request
        .uri()
        .authority()
        .ok_or(Failure::BadRequest("CONNECT needs a host:port target"))?;
    let port = authority
        .port_u16()
        .ok_or(Failure::BadRequest("CONNECT needs a host:port target"))?;
    let host = authority.host().to_owned();
    let destination = format!("{host}:{port}");

    let client_upgrade = hyper::upgrade::on(&mut request);
    let headers = std::mem::take(request.headers_mut());
    // Carries the original capitalization of the header names.
    let extensions = std::mem::take(request.extensions_mut());
    match reach(context, &host, port, headers, extensions).await? {
        Reached::Open(upstream) => {
            spawn_tunnel(context, client_upgrade, upstream, peer.ip(), destination);
        }
        Reached::Refused(response) => return Ok(response),
    }
    Ok(Response::new(full(Bytes::new())))
}

/// A connection that carries bytes to a destination.
pub(super) enum Upstream {
    /// Straight to the destination.
    Direct(TcpStream),
    /// A parent proxy agreed to open a tunnel: the connection is now a pipe to
    /// the destination.
    Tunnel(TokioIo<Upgraded>),
}

impl Upstream {
    /// The local address of a direct connection.
    pub(super) fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Direct(stream) => stream.local_addr().ok(),
            Self::Tunnel(_) => None,
        }
    }
}

impl AsyncRead for Upstream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tunnel(upgraded) => Pin::new(upgraded).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_write(cx, data),
            Self::Tunnel(upgraded) => Pin::new(upgraded).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tunnel(upgraded) => Pin::new(upgraded).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tunnel(upgraded) => Pin::new(upgraded).poll_shutdown(cx),
        }
    }
}

pub(super) enum Reached {
    Open(Upstream),
    /// The parent said no: its answer is for the client.
    Refused(Response<Body>),
}

/// Opens a connection to `host:port`, the way the configuration says: straight
/// to it, or through a parent proxy that is asked to open a tunnel. `host` is
/// as it appears in a URL, so an IPv6 address is in brackets. `headers` are
/// what a parent is told about the client, on top of the configured rules.
///
/// What a PAC script sees of a tunnel is the address it leads to.
pub(super) async fn reach(
    context: &Context,
    host: &str,
    port: u16,
    headers: HeaderMap,
    extensions: Extensions,
) -> Result<Reached, Failure> {
    let address = format!("{host}:{port}");
    let pac_url = if port == 443 {
        format!("https://{}/", host.to_ascii_lowercase())
    } else {
        format!("https://{}:{port}/", host.to_ascii_lowercase())
    };
    // The settings as they are now: what follows is done under them, even if a
    // reload happens meanwhile.
    let live = context.live();
    let mut hops = live.upstreams.hops(&pac_url, host).await?;
    // The parents that accepted a connection and ended it without answering.
    let mut tried = Vec::new();
    loop {
        let (hop, stream) = live
            .upstreams
            .connect(
                hops.clone(),
                &address,
                live.timeouts.connect,
                live.auth.as_deref(),
            )
            .await
            .map_err(|failure| failure.after(std::mem::take(&mut tried)))?;
        let Hop::Parent(parent) = &hop else {
            return Ok(Reached::Open(Upstream::Direct(stream)));
        };
        match connect_through_parent(
            stream,
            parent,
            &address,
            headers.clone(),
            extensions.clone(),
            &live,
        )
        .await
        {
            // Nothing has been tunnelled yet, so the next parent is asked the
            // same thing.
            Err(Failure::NoAnswer(error)) => {
                tried.push(live.upstreams.no_answer(&hop, &error));
                hops.retain(|other| *other != hop);
                if hops.is_empty() {
                    return Err(Failure::ParentsUnavailable(tried));
                }
            }
            other => return other,
        }
    }
}

/// Carries bytes between `client` and `upstream` until one side is done or
/// idle, for a client that is not speaking HTTP (a SOCKS5 client, a forwarded
/// port). Never returns before the tunnel is closed.
/// `peer` and `destination` are logged with the tunnel, matching what the
/// caller logged when it opened it, so a "tunnel closed" can be matched back
/// to it.
pub(super) async fn pipe<C>(
    context: &Context,
    client: C,
    upstream: Upstream,
    peer: IpAddr,
    destination: &str,
) where
    C: AsyncRead + AsyncWrite + Unpin,
{
    relay(
        client,
        upstream,
        context.live().timeouts.tunnel_idle,
        context.force.clone(),
        peer,
        destination,
    )
    .await;
}

/// Relays between the client, once its connection is upgraded, and `upstream`.
/// Unlike the other two callers of [`relay`], nothing has logged this tunnel
/// as opened yet, so this does, with the same `peer`/`destination` fields.
fn spawn_tunnel<U>(
    context: &Context,
    client: OnUpgrade,
    upstream: U,
    peer: IpAddr,
    destination: String,
) where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let idle = context.live().timeouts.tunnel_idle;
    let force = context.force.clone();
    // Tracked, so a graceful shutdown waits for the tunnel.
    context.tracker.spawn(async move {
        match client.await {
            Ok(upgraded) => {
                tracing::debug!(%peer, %destination, "tunnel opened");
                relay(
                    TokioIo::new(upgraded),
                    upstream,
                    idle,
                    force,
                    peer,
                    &destination,
                )
                .await;
            }
            Err(err) => tracing::debug!(%peer, %destination, %err, "CONNECT upgrade failed"),
        }
    });
}

/// Asks a parent proxy, over `stream`, to open a tunnel to `address`. The
/// client's own header fields (User-Agent and the like), if it has any, go
/// along, minus the hop-by-hop ones and its proxy credentials.
///
/// If the parent wants NTLM, the CONNECT request itself opens the exchange and
/// is sent again with the proof. With Negotiate it carries the proof at once.
/// If the connection dies while asking a parent for a Kerberos ticket (some
/// close it right after refusing a bare, credential-less probe), a fresh one
/// to the same parent carries the ticket instead: see the module doc of
/// `parent`. Whichever connection ends up authenticated becomes the tunnel,
/// so none of this is ever reused for anything else.
async fn connect_through_parent(
    stream: TcpStream,
    parent: &HostPort,
    address: &str,
    mut headers: HeaderMap,
    extensions: Extensions,
    live: &Live,
) -> Result<Reached, Failure> {
    strip_hop_by_hop(&mut headers);
    apply_rules(&mut headers, &live.request_headers);
    headers.insert(
        HOST,
        HeaderValue::from_str(address)
            .map_err(|_| Failure::BadRequest("the CONNECT target is invalid"))?,
    );
    let uri = address
        .parse::<Uri>()
        .map_err(|_| Failure::BadRequest("the CONNECT target is invalid"))?;
    let connect = |proof: Option<HeaderValue>| {
        let mut request = Request::new(full(Bytes::new()));
        *request.method_mut() = Method::CONNECT;
        *request.uri_mut() = uri.clone();
        *request.headers_mut() = headers.clone();
        *request.extensions_mut() = extensions.clone();
        if let Some(proof) = proof {
            request.headers_mut().insert(PROXY_AUTHORIZATION, proof);
        }
        request
    };

    let mut sender = handshake(stream).await?;
    let hop = Hop::Parent(parent.clone());

    // Set once a proof has been sent, until the parent has said whether it
    // accepts it.
    let mut admission = None;
    let limit = live.timeouts.response;
    let timed_out = Failure::ResponseTimeout("the parent proxy");
    let response = match &live.auth {
        None => answer_within(limit, sender.send_request(connect(None)))
            .await
            .ok_or(timed_out)?
            .map_err(Failure::first_answer)?,
        Some(auth) => {
            let admitted = auth.admit().await?;
            match auth
                .negotiate(
                    &mut sender,
                    || connect(None),
                    &parent.host,
                    limit,
                    || {
                        Box::pin(async {
                            let stream = live
                                .upstreams
                                .connect_hop(&hop, address, live.timeouts.connect)
                                .await?;
                            handshake(stream).await
                        })
                    },
                )
                .await?
            {
                // The parent asked for nothing: this is its answer.
                Outcome::Answered(response) => response,
                Outcome::Proof { header, made } => {
                    admission = Some(admitted.made_from(made));
                    answer_within(limit, sender.send_request(connect(Some(header))))
                        .await
                        .ok_or(timed_out)?
                        .map_err(Failure::Upstream)?
                }
            }
        }
    };

    // Whatever it said, it said something.
    live.upstreams.worked(&hop);

    if response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        if let Some(sent) = admission {
            return Err(sent.refused());
        }
        tracing::warn!(
            "the parent proxy answered 407: it wants authentication, but no credentials are configured"
        );
    } else if let Some(sent) = admission {
        // Whatever the parent thinks of the tunnel, it took the credentials.
        sent.accepted();
    }

    if response.status().is_success() {
        let upgraded = hyper::upgrade::on(response)
            .await
            .map_err(Failure::Upstream)?;
        return Ok(Reached::Open(Upstream::Tunnel(TokioIo::new(upgraded))));
    }

    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    parts.version = Version::HTTP_11;
    Ok(Reached::Refused(Response::from_parts(
        parts,
        body.boxed_unsync(),
    )))
}

/// Copies bytes both ways until both directions finish, one side fails, no
/// byte has moved in either direction for `idle`, or `force` is cancelled.
/// `peer` and `destination` name the tunnel in every line here, so a "tunnel
/// closed" can be matched back to the "tunnel opened" it closes.
async fn relay<C, U>(
    client: C,
    mut upstream: U,
    idle: Duration,
    force: CancellationToken,
    peer: IpAddr,
    destination: &str,
) where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Arc::new(Activity::new());
    // Watching the client side is enough: every byte in either direction
    // crosses it.
    let mut client = Tracked {
        inner: client,
        activity: activity.clone(),
    };

    tokio::select! {
        result = copy_bidirectional(&mut client, &mut upstream) => match result {
            Ok((from_client, from_upstream)) => {
                tracing::debug!(
                    %peer, %destination, from_client, from_upstream,
                    duration = %activity.elapsed(),
                    "tunnel closed"
                );
            }
            Err(err) => tracing::debug!(
                %peer, %destination, %err,
                duration = %activity.elapsed(),
                "tunnel ended with error"
            ),
        },
        () = wait_until_idle(&activity, idle) => {
            tracing::debug!(
                %peer, %destination,
                duration = %activity.elapsed(),
                "tunnel closed after being idle"
            );
        }
        () = force.cancelled() => {
            tracing::debug!(
                %peer, %destination,
                duration = %activity.elapsed(),
                "tunnel closed at shutdown"
            );
        }
    }
}

/// When the last byte moved, as milliseconds since the tunnel started.
struct Activity {
    started: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(elapsed, Ordering::Relaxed);
    }

    /// How long the tunnel has lived, for a log line: three decimals, so
    /// millisecond precision in seconds (`3.200s`) instead of the nine that
    /// `Duration`'s `Debug` prints by default.
    fn elapsed(&self) -> String {
        format!("{:.3?}", self.started.elapsed())
    }

    fn idle_for(&self) -> Duration {
        self.started
            .elapsed()
            .saturating_sub(Duration::from_millis(self.last_ms.load(Ordering::Relaxed)))
    }
}

async fn wait_until_idle(activity: &Activity, limit: Duration) {
    loop {
        let idle = activity.idle_for();
        if idle >= limit {
            return;
        }
        tokio::time::sleep(limit - idle).await;
    }
}

/// Records activity on every successful read or write of the wrapped stream.
struct Tracked<S> {
    inner: S,
    activity: Arc<Activity>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.touch();
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(poll, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.touch();
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    const IDLE: Duration = Duration::from_millis(300);

    fn peer() -> IpAddr {
        IpAddr::from([127, 0, 0, 1])
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_and_close_propagates() {
        let (mut client, client_side) = duplex(1024);
        let (upstream_side, mut upstream) = duplex(1024);
        let relay = tokio::spawn(relay(
            client_side,
            upstream_side,
            Duration::from_secs(30),
            CancellationToken::new(),
            peer(),
            "test",
        ));

        client.write_all(b"ping").await.unwrap();
        let mut buffer = [0u8; 4];
        upstream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"ping");

        upstream.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"pong");

        drop(client);
        drop(upstream);
        relay.await.unwrap();
    }

    #[tokio::test]
    async fn a_silent_tunnel_is_closed_after_the_idle_timeout() {
        let (mut client, client_side) = duplex(1024);
        let (upstream_side, mut upstream) = duplex(1024);
        let started = Instant::now();
        relay(
            client_side,
            upstream_side,
            IDLE,
            CancellationToken::new(),
            peer(),
            "test",
        )
        .await;

        assert!(started.elapsed() >= IDLE);
        assert!(started.elapsed() < Duration::from_secs(5));
        // Both ends observe the close.
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        assert_eq!(upstream.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn traffic_in_either_direction_keeps_the_tunnel_open() {
        let (mut client, client_side) = duplex(1024);
        let (upstream_side, mut upstream) = duplex(1024);
        let mut relay = tokio::spawn(relay(
            client_side,
            upstream_side,
            IDLE,
            CancellationToken::new(),
            peer(),
            "test",
        ));

        // Well past the idle limit in total, but never idle for that long.
        for round in 0..8 {
            tokio::time::sleep(Duration::from_millis(120)).await;
            let mut byte = [0u8; 1];
            if round % 2 == 0 {
                client.write_all(b"c").await.unwrap();
                upstream.read_exact(&mut byte).await.unwrap();
            } else {
                upstream.write_all(b"u").await.unwrap();
                client.read_exact(&mut byte).await.unwrap();
            }
            assert!(!relay.is_finished(), "closed while active (round {round})");
        }

        // Once traffic stops, the idle timeout ends it.
        tokio::time::timeout(Duration::from_secs(5), &mut relay)
            .await
            .expect("tunnel should close once idle")
            .unwrap();
    }

    #[tokio::test]
    async fn a_forced_shutdown_closes_an_active_tunnel() {
        let (mut client, client_side) = duplex(1024);
        let (upstream_side, mut upstream) = duplex(1024);
        let force = CancellationToken::new();
        let relay = tokio::spawn(relay(
            client_side,
            upstream_side,
            Duration::from_secs(30),
            force.clone(),
            peer(),
            "test",
        ));

        client.write_all(b"x").await.unwrap();
        let mut byte = [0u8; 1];
        upstream.read_exact(&mut byte).await.unwrap();

        force.cancel();
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("relay should stop when forced")
            .unwrap();
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn half_close_is_forwarded_and_the_other_direction_keeps_working() {
        let (mut client, client_side) = duplex(1024);
        let (upstream_side, mut upstream) = duplex(1024);
        let relay = tokio::spawn(relay(
            client_side,
            upstream_side,
            Duration::from_secs(30),
            CancellationToken::new(),
            peer(),
            "test",
        ));

        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        upstream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"request");

        upstream.write_all(b"reply").await.unwrap();
        upstream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");

        relay.await.unwrap();
    }
}
