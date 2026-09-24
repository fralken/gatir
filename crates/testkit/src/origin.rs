//! A scriptable origin server for tests.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::http::{Request, read_request};

/// What the origin sends back for a request: raw bytes, so tests can craft
/// chunked, truncated or malformed responses.
#[derive(Debug, Clone)]
pub struct Reply {
    bytes: Vec<u8>,
    close: bool,
    delay: Duration,
}

impl Reply {
    pub fn raw(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            close: false,
            delay: Duration::ZERO,
        }
    }

    /// A `200 OK` with a `Content-Length` body.
    pub fn ok(body: &str) -> Self {
        Self::raw(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ))
    }

    /// Close the connection after sending this reply.
    pub fn then_close(mut self) -> Self {
        self.close = true;
        self
    }

    /// Wait before sending this reply.
    pub fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

struct State {
    requests: Mutex<Vec<Request>>,
    connections: AtomicUsize,
}

/// Listens on a loopback port, records every request and answers with
/// whatever the handler returns.
pub struct MockOrigin {
    addr: SocketAddr,
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl MockOrigin {
    pub async fn start<F>(handler: F) -> Self
    where
        F: Fn(&Request) -> Reply + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let addr = listener.local_addr().expect("origin address");
        let state = Arc::new(State {
            requests: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
        });
        let handler = Arc::new(handler);

        let task = tokio::spawn({
            let state = state.clone();
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    state.connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(serve(stream, handler.clone(), state.clone()));
                }
            }
        });
        Self { addr, state, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `127.0.0.1:port`, as it appears in URLs and Host headers.
    pub fn authority(&self) -> String {
        self.addr.to_string()
    }

    /// Requests received so far, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.state.requests.lock().expect("requests lock").clone()
    }

    /// Number of TCP connections accepted so far.
    pub fn connection_count(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }
}

impl Drop for MockOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve<F>(stream: TcpStream, handler: Arc<F>, state: Arc<State>)
where
    F: Fn(&Request) -> Reply + Send + Sync + 'static,
{
    let mut reader = BufReader::new(stream);
    while let Ok(Some(request)) = read_request(&mut reader).await {
        state
            .requests
            .lock()
            .expect("requests lock")
            .push(request.clone());
        let reply = handler(&request);
        if !reply.delay.is_zero() {
            tokio::time::sleep(reply.delay).await;
        }
        let stream = reader.get_mut();
        if stream.write_all(&reply.bytes).await.is_err() {
            return;
        }
        if reply.close {
            let _ = stream.shutdown().await;
            return;
        }
    }
}
