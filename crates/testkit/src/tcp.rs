//! A scriptable raw TCP server, for tests of tunnels.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

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
