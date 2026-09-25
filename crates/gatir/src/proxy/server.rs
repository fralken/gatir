//! Listeners, the accept loop and per-connection HTTP serving.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::body::error_response;
use super::parent_auth::ParentAuth;
use super::pool::Pool;
use super::upstream::Upstreams;
use super::{forward, tunnel};
use crate::acl::{Acl, Action};
use crate::config::{Config, HeaderRule, Timeouts};

/// Largest request head (target plus header fields) accepted, in bytes.
///
/// hyper's own buffer limit is approximate (a head somewhat over it can still
/// get through), so `head_size` enforces the exact figure.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Most header fields accepted in one request.
const MAX_HEADERS: usize = 100;

/// State shared by every connection of a running server.
pub(super) struct Context {
    pub access: Acl,
    pub timeouts: Timeouts,
    pub upstreams: Upstreams,
    /// How connections to a parent proxy authenticate; `None` if no
    /// credentials are configured.
    pub auth: Option<ParentAuth>,
    /// Fields set on every request sent upstream.
    pub request_headers: Vec<HeaderRule>,
    /// Idle connections to origin servers and parents, shared by all clients.
    pub pool: Arc<Pool>,
    /// Every task serving a client, so shutdown can wait for them.
    pub tracker: TaskTracker,
    /// Cancelled to begin a graceful shutdown: stop accepting, finish what is
    /// in flight.
    pub shutdown: CancellationToken,
    /// Cancelled to close everything immediately.
    pub force: CancellationToken,
}

/// Bound listeners, ready to accept clients.
pub struct Server {
    listeners: Vec<TcpListener>,
    access: Acl,
    timeouts: Timeouts,
    upstreams: Upstreams,
    auth: Option<ParentAuth>,
    request_headers: Vec<HeaderRule>,
}

impl Server {
    /// Binds every `listen` address of the configuration.
    pub async fn bind(config: &Config) -> io::Result<Self> {
        // Credentials only matter when there is a parent proxy to give them to.
        let auth = match &config.credentials {
            Some(credentials) if !config.parents.is_empty() => Some(
                ParentAuth::new(credentials)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?,
            ),
            _ => None,
        };
        let mut listeners = Vec::with_capacity(config.listen.len());
        for addr in &config.listen {
            let listener = TcpListener::bind(addr).await.map_err(|err| {
                io::Error::new(err.kind(), format!("cannot listen on {addr}: {err}"))
            })?;
            listeners.push(listener);
        }
        Ok(Self {
            listeners,
            access: config.access.clone(),
            timeouts: config.timeouts.clone(),
            upstreams: Upstreams::new(config.parents.clone(), config.no_proxy.clone()),
            auth,
            request_headers: config.request_headers.clone(),
        })
    }

    /// The bound addresses (useful when the configuration asked for port 0).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }

    /// Serves clients until shut down.
    ///
    /// Cancelling `shutdown` stops accepting new connections and lets active
    /// requests and tunnels finish, for at most `timeouts.shutdown_grace`;
    /// idle connections close at once. Cancelling `force`, or the end of the
    /// grace period, closes everything that is left. Returns once every
    /// connection is gone.
    pub async fn run(self, shutdown: CancellationToken, force: CancellationToken) {
        let context = Arc::new(Context {
            access: self.access,
            timeouts: self.timeouts,
            upstreams: self.upstreams,
            auth: self.auth,
            request_headers: self.request_headers,
            pool: Arc::new(Pool::default()),
            tracker: TaskTracker::new(),
            shutdown: shutdown.clone(),
            force: force.clone(),
        });
        for listener in self.listeners {
            context
                .tracker
                .spawn(accept_loop(listener, context.clone()));
        }

        shutdown.cancelled().await;
        context.tracker.close();
        let grace = context.timeouts.shutdown_grace;
        tracing::info!(
            grace_secs = grace.as_secs(),
            "shutting down, waiting for active connections"
        );

        tokio::select! {
            () = context.tracker.wait() => {}
            () = tokio::time::sleep(grace) => {
                tracing::warn!("grace period over, closing the remaining connections");
                force.cancel();
                context.tracker.wait().await;
            }
            () = force.cancelled() => {
                tracing::warn!("forced shutdown, closing the remaining connections");
                context.tracker.wait().await;
            }
        }
    }
}

async fn accept_loop(listener: TcpListener, context: Arc<Context>) {
    loop {
        let accepted = tokio::select! {
            () = context.shutdown.cancelled() => return,
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
            context.tracker.spawn(deny(stream));
            continue;
        }
        context
            .tracker
            .spawn(serve_connection(stream, peer, context.clone()));
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
    let shutdown = context.shutdown.clone();
    let force = context.force.clone();
    let service = service_fn(move |request| {
        let context = context.clone();
        async move {
            if head_size(&request) > MAX_HEAD_BYTES {
                return Ok(error_response(
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "The request headers are too large",
                    true,
                ));
            }
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
        .preserve_header_case(true)
        .max_buf_size(MAX_HEAD_BYTES)
        .max_headers(MAX_HEADERS)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    let mut connection = std::pin::pin!(connection);

    let mut draining = false;
    loop {
        tokio::select! {
            result = connection.as_mut() => {
                if let Err(err) = result {
                    tracing::debug!(%peer, %err, "client connection ended with error");
                }
                return;
            }
            // Finish the request in flight, then close; an idle connection
            // closes immediately.
            () = shutdown.cancelled(), if !draining => {
                draining = true;
                connection.as_mut().graceful_shutdown();
            }
            () = force.cancelled() => {
                tracing::debug!(%peer, "client connection closed at shutdown");
                return;
            }
        }
    }
}

/// Size of the request head, counting the request target and every field.
fn head_size(request: &Request<Incoming>) -> usize {
    let target = request.uri().to_string().len();
    let fields: usize = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum();
    target + fields
}
