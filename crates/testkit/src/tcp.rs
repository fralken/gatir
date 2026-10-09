//! A scriptable raw TCP server, for tests of tunnels.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Listens on a loopback port and runs `handler` for every accepted
/// connection, so a test decides byte by byte what the peer does.
pub struct TcpServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl TcpServer {
    pub async fn start<F, Fut>(handler: F) -> Self
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let addr = listener.local_addr().expect("server address");
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(handler(stream));
            }
        });
        Self { addr, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `127.0.0.1:port`, as used in a CONNECT request line.
    pub fn authority(&self) -> String {
        self.addr.to_string()
    }
}

impl Drop for TcpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// How a server that cannot serve gets rid of a connection it accepted.
#[derive(Clone, Copy, Debug)]
pub enum Hangup {
    /// Closes it properly (FIN).
    Close,
    /// Resets it (RST): what a listener with nothing behind it does.
    Reset,
}

/// A server that accepts every connection and ends it at once, without
/// reading a byte, and counts them.
pub struct DeadServer {
    server: TcpServer,
    accepted: Arc<AtomicUsize>,
}

impl DeadServer {
    pub async fn start(hangup: Hangup) -> Self {
        let accepted = Arc::new(AtomicUsize::new(0));
        let server = TcpServer::start({
            let accepted = accepted.clone();
            move |stream| {
                accepted.fetch_add(1, Ordering::SeqCst);
                async move {
                    if matches!(hangup, Hangup::Reset) {
                        stream.set_zero_linger().expect("set SO_LINGER");
                    }
                    drop(stream);
                }
            }
        })
        .await;
        Self { server, accepted }
    }

    pub fn addr(&self) -> SocketAddr {
        self.server.addr()
    }

    /// How many connections were accepted so far.
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}
