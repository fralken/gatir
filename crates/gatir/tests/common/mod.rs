//! Helpers shared by the integration tests.

// Each test file uses a different subset of these helpers.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gatir::auth::TokenSource;
use gatir::config::{Config, Overrides};
use gatir::pac::Trust;
use gatir::proxy::{Server, Services};
use gatir_testkit::http::{RawClient, Response};
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};
use gatir_testkit::tcp::TcpServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub struct TestProxy {
    pub addr: SocketAddr,
    /// The forwarded ports, in the order of the configuration.
    pub tunnels: Vec<SocketAddr>,
    /// The SOCKS5 server, if there is one.
    pub socks5: Vec<SocketAddr>,
    /// Replaces the settings while the proxy runs.
    pub reloader: gatir::proxy::Reloader,
    pub shutdown: CancellationToken,
    pub force: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl TestProxy {
    /// Waits up to `limit` for `Server::run` to return.
    pub async fn finished_within(&mut self, limit: Duration) -> bool {
        let Some(task) = self.task.as_mut() else {
            return true;
        };
        let finished = tokio::time::timeout(limit, task).await.is_ok();
        if finished {
            self.task = None;
        }
        finished
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.force.cancel();
    }
}

/// Starts a proxy on a free loopback port. `extra` is appended to the
/// configuration and may contain further top-level keys and tables.
pub async fn start_proxy(extra: &str) -> TestProxy {
    run(bind(extra, None, None).await)
}

/// Like [`start_proxy`], with `trust` for the certificates of `https://` PAC
/// addresses.
pub async fn start_proxy_trusting(extra: &str, trust: Trust) -> TestProxy {
    run(bind(extra, None, Some(trust)).await)
}

/// Like [`start_proxy`], with Negotiate tokens from `tokens` in place of the
/// system's Kerberos tickets.
pub async fn start_proxy_with_tokens(extra: &str, tokens: Arc<dyn TokenSource>) -> TestProxy {
    run(bind(extra, Some(tokens), None).await)
}

async fn bind(extra: &str, tokens: Option<Arc<dyn TokenSource>>, trust: Option<Trust>) -> Server {
    let toml = format!("listen = [\"127.0.0.1:0\"]\n{extra}");
    let config = Config::from_toml_str(&toml, Overrides::default()).expect("test configuration");
    let services = Services {
        tokens,
        trust: trust.unwrap_or_else(Trust::system),
        ..Services::default()
    };
    Server::bind_with(&config, services)
        .await
        .expect("bind the proxy")
}

fn run(server: Server) -> TestProxy {
    let addr = server.local_addrs()[0];
    let tunnels = server
        .tunnel_addrs()
        .into_iter()
        .map(|(addr, _)| addr)
        .collect();
    let shutdown = CancellationToken::new();
    let force = CancellationToken::new();
    let socks5 = server.socks5_addrs();
    let reloader = server.reloader();
    let task = tokio::spawn(server.run(shutdown.clone(), force.clone()));
    TestProxy {
        addr,
        tunnels,
        socks5,
        reloader,
        shutdown,
        force,
        task: Some(task),
    }
}

/// Configuration for a proxy whose only parent wants NTLM: the parent, and the
/// credentials of the account `alice` in the domain `CORP`.
pub fn ntlm_parent_config(parent: SocketAddr, method: &str, password: &str) -> String {
    format!(
        "parents = [\"{parent}\"]\n\
         [credentials]\nusername = \"alice\"\ndomain = \"CORP\"\npassword = \"{password}\"\n\
         method = \"{method}\"\n"
    )
}

/// Sends `request` on a new connection to the proxy, and reads the answer.
pub async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>) -> Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

/// A server that answers every request with `name`: a parent, or an origin,
/// that a test can tell apart from the others.
pub async fn named(name: &'static str) -> MockOrigin {
    MockOrigin::start(move |_| Reply::ok(name)).await
}

/// A parent that wants NTLM from `alice` in `CORP`, password `s3cret`. Once a
/// connection is authenticated, it opens tunnels that echo, answers `HEAD`
/// with an empty `200`, and answers anything else with the method and the
/// size of the body (`"POST 5 bytes"`).
pub async fn alice_parent(options: Options) -> MockNtlmParent {
    MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        options,
        |request| match request.method.as_str() {
            "CONNECT" => Reply::raw("HTTP/1.1 200 Connection Established\r\n\r\n").then_echo(),
            "HEAD" => Reply::raw("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n"),
            method => Reply::ok(&format!("{method} {} bytes", request.body.len())),
        },
    )
    .await
}

/// A proxy-style GET request (absolute-form target).
pub fn get(authority: &str, path: &str, extra_headers: &str) -> String {
    format!("GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\n{extra_headers}\r\n")
}

/// FNV-1a, to compare large bodies without keeping two copies around.
pub fn fnv(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

pub fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}

// ---- CONNECT helpers ----

pub fn connect_request(authority: &str) -> String {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
}

/// Opens a tunnel to `authority` and returns the client, positioned right after
/// the `200` head.
pub async fn open_tunnel(proxy: &TestProxy, authority: &str) -> RawClient {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(connect_request(authority)).await.unwrap();
    let response = client.read_response(true).await.unwrap();
    assert_eq!(response.status, 200, "{}", response.body_text());
    client
}

/// A destination that sends back whatever it receives.
pub async fn echo_server() -> TcpServer {
    TcpServer::start(|mut stream| async move {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
    .await
}

pub async fn eventually(what: &str, condition: impl Fn() -> bool) {
    for _ in 0..50 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}
