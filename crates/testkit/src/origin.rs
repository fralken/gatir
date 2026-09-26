//! A scriptable origin server for tests.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_rustls::TlsAcceptor;

use crate::http::{Request, read_request};
use crate::tls::Identity;

/// What the origin sends back for a request: raw bytes, so tests can craft
/// chunked, truncated or malformed responses.
#[derive(Debug, Clone)]
pub struct Reply {
    pub(crate) bytes: Vec<u8>,
    pub(crate) close: bool,
    pub(crate) echo: bool,
    pub(crate) delay: Duration,
}

impl Reply {
    pub fn raw(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            close: false,
            echo: false,
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

    /// After this reply, echo back every byte received (an answer to CONNECT
    /// that turns the connection into a tunnel to an echo server).
    pub fn then_echo(mut self) -> Self {
        self.echo = true;
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
    /// The server name each TLS client asked for, in handshake order.
    server_names: Mutex<Vec<Option<String>>>,
    /// Handshakes that did not complete: the client refused the certificate,
    /// or was not speaking TLS.
    failed_handshakes: AtomicUsize,
    /// One per accepted connection, so dropping the origin closes them all.
    tasks: Mutex<Vec<AbortHandle>>,
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
        Self::listen(None, handler).await
    }

    /// Like [`MockOrigin::start`], but every connection speaks TLS first,
    /// presenting `identity`.
    pub async fn start_tls<F>(identity: &Identity, handler: F) -> Self
    where
        F: Fn(&Request) -> Reply + Send + Sync + 'static,
    {
        Self::listen(Some(identity.acceptor()), handler).await
    }

    async fn listen<F>(tls: Option<TlsAcceptor>, handler: F) -> Self
    where
        F: Fn(&Request) -> Reply + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let addr = listener.local_addr().expect("origin address");
        let state = Arc::new(State {
            requests: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            server_names: Mutex::new(Vec::new()),
            failed_handshakes: AtomicUsize::new(0),
            tasks: Mutex::new(Vec::new()),
        });
        let handler = Arc::new(handler);

        let task = tokio::spawn({
            let state = state.clone();
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    state.connections.fetch_add(1, Ordering::SeqCst);
                    let (handler, shared, tls) = (handler.clone(), state.clone(), tls.clone());
                    let connection = tokio::spawn(async move {
                        match tls {
                            None => serve(stream, handler, shared).await,
                            Some(acceptor) => match acceptor.accept(stream).await {
                                Ok(stream) => {
                                    let name = stream.get_ref().1.server_name().map(str::to_owned);
                                    shared.server_names.lock().expect("names lock").push(name);
                                    serve(stream, handler, shared).await;
                                }
                                Err(_) => {
                                    shared.failed_handshakes.fetch_add(1, Ordering::SeqCst);
                                }
                            },
                        }
                    });
                    state
                        .tasks
                        .lock()
                        .expect("tasks lock")
                        .push(connection.abort_handle());
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

    /// The server name each client that completed a TLS handshake asked for
    /// (`None` when it sent none, as for an IP address).
    pub fn server_names(&self) -> Vec<Option<String>> {
        self.state.server_names.lock().expect("names lock").clone()
    }

    /// TLS handshakes that did not complete.
    pub fn failed_handshakes(&self) -> usize {
        self.state.failed_handshakes.load(Ordering::SeqCst)
    }
}

/// Dropping the origin makes it disappear: it stops listening and closes
/// every connection it had open.
impl Drop for MockOrigin {
    fn drop(&mut self) {
        self.task.abort();
        for connection in self.state.tasks.lock().expect("tasks lock").iter() {
            connection.abort();
        }
    }
}

async fn serve<S, F>(stream: S, handler: Arc<F>, state: Arc<State>)
where
    S: AsyncRead + AsyncWrite + Unpin,
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
        if reply.echo {
            echo(&mut reader).await;
            return;
        }
    }
}

/// Sends back what the peer sends until it closes.
async fn echo<S: AsyncRead + AsyncWrite + Unpin>(reader: &mut BufReader<S>) {
    let mut buffer = [0u8; 4096];
    loop {
        let count = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        if reader.get_mut().write_all(&buffer[..count]).await.is_err() {
            return;
        }
    }
}
