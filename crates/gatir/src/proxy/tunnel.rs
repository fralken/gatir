//! CONNECT tunnels: an opaque byte pipe between the client and a destination.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional};
use tokio_util::sync::CancellationToken;

use super::body::{Body, full};
use super::failure::{Failure, connect_tcp};
use super::server::Context;

pub(super) async fn handle(
    request: Request<Incoming>,
    context: &Context,
    peer: SocketAddr,
) -> Response<Body> {
    let destination = request.uri().authority().map(ToString::to_string);
    let response = match open(request, context).await {
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

/// Connects to the destination first, so a failure can still be reported to the
/// client as an HTTP error; only then is the tunnel promised with a 200.
async fn open(request: Request<Incoming>, context: &Context) -> Result<Response<Body>, Failure> {
    let authority = request
        .uri()
        .authority()
        .ok_or(Failure::BadRequest("CONNECT needs a host:port target"))?;
    let port = authority
        .port_u16()
        .ok_or(Failure::BadRequest("CONNECT needs a host:port target"))?;
    let address = format!("{}:{port}", authority.host());

    let upstream = connect_tcp(&address, context.timeouts.connect).await?;

    let idle = context.timeouts.tunnel_idle;
    let force = context.force.clone();
    let upgrade = hyper::upgrade::on(request);
    // Tracked, so a graceful shutdown waits for the tunnel.
    context.tracker.spawn(async move {
        match upgrade.await {
            Ok(upgraded) => relay(TokioIo::new(upgraded), upstream, idle, force).await,
            Err(err) => tracing::debug!(%err, "CONNECT upgrade failed"),
        }
    });
    Ok(Response::new(full(Bytes::new())))
}

/// Copies bytes both ways until both directions finish, one side fails, no
/// byte has moved in either direction for `idle`, or `force` is cancelled.
async fn relay<C, U>(client: C, mut upstream: U, idle: Duration, force: CancellationToken)
where
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
                tracing::debug!(from_client, from_upstream, "tunnel closed");
            }
            Err(err) => tracing::debug!(%err, "tunnel ended with error"),
        },
        () = wait_until_idle(&activity, idle) => tracing::debug!("tunnel closed after being idle"),
        () = force.cancelled() => tracing::debug!("tunnel closed at shutdown"),
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

    #[tokio::test]
    async fn bytes_flow_both_ways_and_close_propagates() {
        let (mut client, client_side) = duplex(1024);
        let (upstream_side, mut upstream) = duplex(1024);
        let relay = tokio::spawn(relay(
            client_side,
            upstream_side,
            Duration::from_secs(30),
            CancellationToken::new(),
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
        relay(client_side, upstream_side, IDLE, CancellationToken::new()).await;

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
