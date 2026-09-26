//! Listeners, the accept loop and per-connection HTTP serving.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, PoisonError, RwLock};
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
use super::parent::ParentAuth;
use super::pool::Pool;
use super::portfwd;
use super::socks5;
use super::upstream::Upstreams;
use super::{forward, tunnel};
use crate::acl::{Acl, Action};
use crate::auth::TokenSource;
use crate::config::{
    Config, Credentials, Fixed, HeaderRule, HostPort, PacConfig, Socks5Credentials, Timeouts,
};
use crate::pac::{PacSource, Trust};

/// Largest request head (target plus header fields) accepted, in bytes.
///
/// hyper's own buffer limit is approximate (a head somewhat over it can still
/// get through), so `head_size` enforces the exact figure.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Most header fields accepted in one request.
const MAX_HEADERS: usize = 100;

/// The settings a reload replaces: where requests go, who may make them, and
/// how. Every request, tunnel and SOCKS5 client works on the one it found when
/// it began, so a reload never changes what is under it.
pub(super) struct Live {
    pub access: Acl,
    pub timeouts: Timeouts,
    pub upstreams: Upstreams,
    /// How connections to a parent proxy authenticate; `None` if no
    /// credentials are configured.
    pub auth: Option<Arc<ParentAuth>>,
    /// Fields set on every request sent upstream.
    pub request_headers: Vec<HeaderRule>,
    /// Who may use the SOCKS5 server (anyone, if not set).
    pub socks5_credentials: Option<Arc<Socks5Credentials>>,
    /// What the next reload compares with, to keep what did not change: the
    /// script (with the settings it was started with), and the credentials
    /// (whose record with the parent goes with `auth`).
    pac: Option<(PacConfig, Arc<PacSource>)>,
    credentials: Option<Credentials>,
}

type LiveCell = Arc<RwLock<Arc<Live>>>;

/// State shared by every connection of a running server.
pub(super) struct Context {
    live: LiveCell,
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

impl Context {
    /// The settings as they are now.
    pub(super) fn live(&self) -> Arc<Live> {
        self.live
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Builds the settings of `config`. `previous` are those in use, from which
/// the PAC script is kept if its settings did not change (it holds the last
/// version that worked), and so are the credentials' record with the parent
/// (an account refused recently is not tried again for it to be refused).
///
/// The second value is the script that was kept, if any.
async fn build_live(
    config: &Config,
    previous: Option<&Live>,
    tokens: &Option<Arc<dyn TokenSource>>,
    trust: &Trust,
) -> io::Result<(Live, Option<Arc<PacSource>>)> {
    // A PAC file that is missing or wrong is found here, not on the first request.
    let (pac, kept_script) = match (&config.pac, previous.and_then(|live| live.pac.as_ref())) {
        (Some(settings), Some((used, source))) if used == settings => (
            Some((settings.clone(), source.clone())),
            Some(source.clone()),
        ),
        (Some(settings), _) => (
            Some((
                settings.clone(),
                PacSource::start_with(settings, trust.clone()).await?,
            )),
            None,
        ),
        (None, _) => (None, None),
    };
    // Credentials only matter when there is a parent proxy to give them to.
    let auth = match &config.credentials {
        Some(credentials) if !config.parents.is_empty() || pac.is_some() => {
            let kept = previous.and_then(|live| {
                let unchanged = live
                    .credentials
                    .as_ref()
                    .is_some_and(|used| used.same_as(credentials));
                live.auth.clone().filter(|_| unchanged)
            });
            match kept {
                Some(auth) => Some(auth),
                None => Some(Arc::new(
                    ParentAuth::new(credentials, tokens.clone()).map_err(|err| {
                        io::Error::new(io::ErrorKind::InvalidInput, err.to_string())
                    })?,
                )),
            }
        }
        _ => None,
    };
    let upstreams = Upstreams::new(
        config.parents.clone(),
        config.no_proxy.clone(),
        pac.as_ref().map(|(_, source)| source.clone()),
    );
    let live = Live {
        access: config.access.clone(),
        timeouts: config.timeouts.clone(),
        upstreams,
        auth,
        request_headers: config.request_headers.clone(),
        socks5_credentials: config
            .socks5
            .as_ref()
            .and_then(|socks5| socks5.credentials.clone())
            .map(Arc::new),
        pac,
        credentials: config.credentials.clone(),
    };
    Ok((live, kept_script))
}

/// Replaces the settings of a running server with those of a configuration
/// read again.
#[derive(Clone)]
pub struct Reloader {
    live: LiveCell,
    pool: Arc<Pool>,
    tokens: Option<Arc<dyn TokenSource>>,
    trust: Trust,
    /// What the server was started with, and no reload can change.
    fixed: Fixed,
    /// A reload at a time.
    turn: Arc<tokio::sync::Mutex<()>>,
}

impl Reloader {
    /// Applies `config`, or changes nothing and says why not: a PAC file that
    /// cannot be used, or credentials that cannot be turned into a way of
    /// authenticating, leave the server as it was.
    ///
    /// Returns the settings of `config` that still need a new start, by name
    /// (where gatir listens, and the log level); the server goes on with the
    /// values it had for those.
    pub async fn apply(&self, config: &Config) -> io::Result<Vec<&'static str>> {
        let _turn = self.turn.lock().await;
        let previous = self
            .live
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let (live, kept_script) =
            build_live(config, Some(&previous), &self.tokens, &self.trust).await?;

        // First the settings, then the pool: a request reads them the other way
        // round, so a connection is never taken for newer than it is.
        *self.live.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(live);
        // Connections opened under the old settings may have authenticated as
        // someone else, or lead to another parent: none is reused.
        self.pool.clear();
        // A script that stayed is looked at now: reloading is also how a person
        // says that it changed.
        if let Some(script) = kept_script {
            script.refresh_soon();
        }
        Ok(self.fixed.differences(&config.fixed()))
    }
}

/// Bound listeners, ready to accept clients.
pub struct Server {
    listeners: Vec<TcpListener>,
    /// Ports forwarded to a fixed destination, each with its destination.
    tunnels: Vec<(TcpListener, HostPort)>,
    /// SOCKS5 listeners.
    socks5: Vec<TcpListener>,
    live: LiveCell,
    pool: Arc<Pool>,
    reloader: Reloader,
}

impl Server {
    /// Binds every `listen` address of the configuration.
    pub async fn bind(config: &Config) -> io::Result<Self> {
        Self::bind_with(config, None, Trust::system()).await
    }

    /// Like [`Server::bind`], taking the Negotiate tokens from `tokens`
    /// instead of the system's Kerberos tickets. For tests, which have none.
    pub async fn bind_with_tokens(
        config: &Config,
        tokens: Arc<dyn TokenSource>,
    ) -> io::Result<Self> {
        Self::bind_with(config, Some(tokens), Trust::system()).await
    }

    /// Like [`Server::bind`], with `trust` deciding which certificate
    /// authorities an `https://` PAC address may chain to. For tests, which
    /// run an authority of their own.
    pub async fn bind_with_trust(config: &Config, trust: Trust) -> io::Result<Self> {
        Self::bind_with(config, None, trust).await
    }

    async fn bind_with(
        config: &Config,
        tokens: Option<Arc<dyn TokenSource>>,
        trust: Trust,
    ) -> io::Result<Self> {
        let (live, _) = build_live(config, None, &tokens, &trust).await?;
        let mut listeners = Vec::with_capacity(config.listen.len());
        for addr in &config.listen {
            let listener = TcpListener::bind(addr).await.map_err(|err| {
                io::Error::new(err.kind(), format!("cannot listen on {addr}: {err}"))
            })?;
            listeners.push(listener);
        }
        let mut tunnels = Vec::with_capacity(config.tunnels.len());
        for tunnel in &config.tunnels {
            let listener = TcpListener::bind(tunnel.listen).await.map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!("cannot listen on {} for a tunnel: {err}", tunnel.listen),
                )
            })?;
            tunnels.push((listener, tunnel.target.clone()));
        }
        let mut socks5 = Vec::new();
        if let Some(config) = &config.socks5 {
            for addr in &config.listen {
                let listener = TcpListener::bind(addr).await.map_err(|err| {
                    io::Error::new(
                        err.kind(),
                        format!("cannot listen on {addr} for SOCKS5: {err}"),
                    )
                })?;
                socks5.push(listener);
            }
        }
        let live: LiveCell = Arc::new(RwLock::new(Arc::new(live)));
        let pool = Arc::new(Pool::default());
        Ok(Self {
            listeners,
            tunnels,
            socks5,
            reloader: Reloader {
                live: live.clone(),
                pool: pool.clone(),
                tokens,
                trust,
                fixed: config.fixed(),
                turn: Arc::new(tokio::sync::Mutex::new(())),
            },
            live,
            pool,
        })
    }

    /// A handle that replaces the settings of this server while it runs.
    pub fn reloader(&self) -> Reloader {
        self.reloader.clone()
    }

    /// The bound addresses (useful when the configuration asked for port 0).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }

    /// The bound addresses of the forwarded ports, with where each leads.
    pub fn tunnel_addrs(&self) -> Vec<(SocketAddr, HostPort)> {
        self.tunnels
            .iter()
            .filter_map(|(listener, target)| Some((listener.local_addr().ok()?, target.clone())))
            .collect()
    }

    /// The bound addresses of the SOCKS5 server.
    pub fn socks5_addrs(&self) -> Vec<SocketAddr> {
        self.socks5
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
            live: self.live,
            pool: self.pool,
            tracker: TaskTracker::new(),
            shutdown: shutdown.clone(),
            force: force.clone(),
        });
        for listener in self.listeners {
            context
                .tracker
                .spawn(accept(listener, context.clone(), serve_connection, deny));
        }
        for listener in self.socks5 {
            context.tracker.spawn(accept(
                listener,
                context.clone(),
                socks5::serve,
                // Nothing to say in a protocol that has no words for it.
                |_stream| async {},
            ));
        }
        for (listener, target) in self.tunnels {
            context.tracker.spawn(accept(
                listener,
                context.clone(),
                move |stream, peer, context| portfwd::serve(stream, peer, target.clone(), context),
                // Nothing to say in a protocol that has no words for it.
                |_stream| async {},
            ));
        }

        shutdown.cancelled().await;
        context.tracker.close();
        let grace = context.live().timeouts.shutdown_grace;
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

/// Accepts clients on `listener` until shutdown. Each one the access rules
/// allow is handed to `serve`, in a task the shutdown waits for; each one they
/// reject is handed to `denied`.
pub(super) async fn accept<S, SF, D, DF>(
    listener: TcpListener,
    context: Arc<Context>,
    serve: S,
    denied: D,
) where
    S: Fn(TcpStream, SocketAddr, Arc<Context>) -> SF,
    SF: Future<Output = ()> + Send + 'static,
    D: Fn(TcpStream) -> DF,
    DF: Future<Output = ()> + Send + 'static,
{
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

        if context.live().access.check(peer.ip()) == Action::Deny {
            tracing::info!(peer = %peer.ip(), "connection denied by the access rules");
            context.tracker.spawn(denied(stream));
            continue;
        }
        context.tracker.spawn(serve(stream, peer, context.clone()));
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

    let client_idle = context.live().timeouts.client_idle;
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
