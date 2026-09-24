//! Listeners, the accept loop and per-connection HTTP serving.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::Method;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::{forward, tunnel};
use crate::acl::{Acl, Action};
use crate::config::{Config, Timeouts};

/// Largest request head (start line plus header fields) accepted, in bytes.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Most header fields accepted in one request.
const MAX_HEADERS: usize = 100;

/// Settings shared by every connection.
pub(super) struct Context {
    pub access: Acl,
    pub timeouts: Timeouts,
}

/// Bound listeners, ready to accept clients.
pub struct Server {
    listeners: Vec<TcpListener>,
    context: Arc<Context>,
}

impl Server {
    /// Binds every `listen` address of the configuration.
    pub async fn bind(config: &Config) -> io::Result<Self> {
        let mut listeners = Vec::with_capacity(config.listen.len());
        for addr in &config.listen {
            let listener = TcpListener::bind(addr).await.map_err(|err| {
                io::Error::new(err.kind(), format!("cannot listen on {addr}: {err}"))
            })?;
            listeners.push(listener);
        }
        Ok(Self {
            listeners,
            context: Arc::new(Context {
                access: config.access.clone(),
                timeouts: config.timeouts.clone(),
            }),
        })
    }

    /// The bound addresses (useful when the configuration asked for port 0).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }

    /// Serves clients until `shutdown` is cancelled.
    pub async fn run(self, shutdown: CancellationToken) {
        let tracker = TaskTracker::new();
        for listener in self.listeners {
            tracker.spawn(accept_loop(
                listener,
                self.context.clone(),
                shutdown.clone(),
                tracker.clone(),
            ));
        }
        shutdown.cancelled().await;
    }
}

async fn accept_loop(
    listener: TcpListener,
    context: Arc<Context>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
) {
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(err) => {
                // Typically out of file descriptors: back off instead of spinning.
                tracing::warn!(%err, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        if context.access.check(peer.ip()) == Action::Deny {
            tracing::info!(peer = %peer.ip(), "connection denied by the access rules");
            tracker.spawn(deny(stream));
            continue;
        }
        tracker.spawn(serve_connection(stream, peer, context.clone()));
    }
}

/// Answers a client that the access rules reject, without parsing its request.
async fn deny(mut stream: TcpStream) {
    const BODY: &str = "Access denied for this address\n";
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    );
    if stream.write_all(response.as_bytes()).await.is_err() {
        return;
    }
    let _ = stream.shutdown().await;
    // Let the client finish sending: closing with unread data would reset the
    // connection and could discard the response before the client reads it.
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let mut sink = [0u8; 1024];
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await;
}

async fn serve_connection(stream: TcpStream, peer: SocketAddr, context: Arc<Context>) {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(%peer, %err, "cannot set TCP_NODELAY on the client connection");
    }

    let client_idle = context.timeouts.client_idle;
    let service = service_fn(move |request| {
        let context = context.clone();
        async move {
            let response = if request.method() == Method::CONNECT {
                tunnel::handle(request, &context, peer).await
            } else {
                forward::handle(request, &context, peer).await
            };
            Ok::<_, Infallible>(response)
        }
    });

    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(client_idle)
        .half_close(true)
        .max_buf_size(MAX_HEAD_BYTES)
        .max_headers(MAX_HEADERS)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();

    if let Err(err) = connection.await {
        tracing::debug!(%peer, %err, "client connection ended with error");
    }
}
