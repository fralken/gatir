//! An origin server that demands NTLM authentication directly — `401` and
//! `WWW-Authenticate`, on its own behalf — as opposed to [`crate::ntlm_parent`],
//! which speaks the proxy side of the exchange (`407`, `Proxy-Authenticate`).
//! The account, the challenge and its verification are the same code, reused
//! from there: only the header names and the status code differ.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{AbortHandle, JoinHandle};

use crate::http::{Request, read_request};
use crate::ntlm_parent::{
    Account, accepts, challenge_for, challenge_for_account, message_type, ntlm_token,
};
use crate::origin::Reply;

/// A request as the origin saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub request: Request,
    /// The accepted connection that carried it, counting from 1.
    pub connection: usize,
    /// The type (1 or 3) of the NTLM message in `Authorization`, if any.
    pub message: Option<u32>,
    /// True if the handler answered it, false if it got a `401`.
    pub served: bool,
}

struct Shared {
    account: Account,
    handler: Box<dyn Fn(&Request) -> Reply + Send + Sync>,
    seen: Mutex<Vec<Seen>>,
    connections: AtomicUsize,
    /// One per accepted connection, so dropping the origin closes them all.
    tasks: Mutex<Vec<AbortHandle>>,
}

/// Listens on a loopback port and answers like a web server behind which
/// `account` is the only identity NTLM accepts. Requests that pass
/// authentication are answered by the handler.
pub struct MockNtlmOrigin {
    addr: SocketAddr,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl MockNtlmOrigin {
    pub async fn start<F>(account: Account, handler: F) -> Self
    where
        F: Fn(&Request) -> Reply + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local address");
        let shared = Arc::new(Shared {
            account,
            handler: Box::new(handler),
            seen: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            tasks: Mutex::new(Vec::new()),
        });

        let accepting = shared.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let id = accepting.connections.fetch_add(1, Ordering::Relaxed) + 1;
                let shared = accepting.clone();
                let handle = tokio::spawn(serve(stream, shared, id)).abort_handle();
                accepting.tasks.lock().expect("tasks lock").push(handle);
            }
        });

        Self { addr, shared, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn requests(&self) -> Vec<Seen> {
        self.shared.seen.lock().expect("seen lock").clone()
    }

    pub fn connection_count(&self) -> usize {
        self.shared.connections.load(Ordering::Relaxed)
    }
}

impl Drop for MockNtlmOrigin {
    fn drop(&mut self) {
        self.task.abort();
        for connection in self.shared.tasks.lock().expect("tasks lock").iter() {
            connection.abort();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Anonymous,
    /// The challenge sent, waiting for the answer.
    Challenged([u8; 8]),
    Authenticated,
}

async fn serve(stream: TcpStream, shared: Arc<Shared>, id: usize) {
    let mut reader = BufReader::new(stream);
    let mut state = State::Anonymous;

    while let Ok(Some(request)) = read_request(&mut reader).await {
        let token = request.headers.get("authorization").and_then(ntlm_token);
        let message = token.as_deref().and_then(message_type);
        let record = |answered: bool| {
            shared.seen.lock().expect("seen lock").push(Seen {
                request: request.clone(),
                connection: id,
                message,
                served: answered,
            });
        };

        let refusal: Option<Vec<u8>> = match (message, &token) {
            (Some(1), _) => {
                let challenge = challenge_for(id);
                state = State::Challenged(challenge);
                Some(challenge_reply(&shared.account, challenge))
            }
            (Some(3), Some(token)) => match state {
                State::Challenged(challenge)
                    if accepts(&shared.account, token, &challenge, None) =>
                {
                    state = State::Authenticated;
                    None
                }
                _ => {
                    state = State::Anonymous;
                    Some(unauthorized("NTLM".to_owned()))
                }
            },
            _ if state == State::Authenticated => None,
            _ => {
                state = State::Anonymous;
                Some(unauthorized("NTLM".to_owned()))
            }
        };

        if let Some(bytes) = refusal {
            record(false);
            if reader.get_mut().write_all(&bytes).await.is_err() {
                return;
            }
            continue;
        }

        record(true);
        let reply = (shared.handler)(&request);
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

fn challenge_reply(account: &Account, challenge: [u8; 8]) -> Vec<u8> {
    let message = challenge_for_account(account, &challenge, None);
    unauthorized(format!("NTLM {}", STANDARD.encode(message)))
}

/// A `401` with the given `WWW-Authenticate` field.
fn unauthorized(field: String) -> Vec<u8> {
    const BODY: &str = "Unauthorized\n";
    let mut head = String::from("HTTP/1.1 401 Unauthorized\r\n");
    head.push_str(&format!("WWW-Authenticate: {field}\r\n"));
    head.push_str("Content-Type: text/plain\r\n");
    head.push_str(&format!("Content-Length: {}\r\n\r\n{BODY}", BODY.len()));
    head.into_bytes()
}
