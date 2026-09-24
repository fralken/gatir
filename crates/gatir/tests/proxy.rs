//! End-to-end tests of the proxy against a scripted origin server.
//!
//! Clients and origins speak raw bytes through `gatir-testkit`, which parses
//! HTTP by hand, so these tests do not depend on the HTTP library the proxy
//! is built on.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gatir::config::{Config, Overrides};
use gatir::proxy::Server;
use gatir_testkit::closed_port;
use gatir_testkit::http::RawClient;
use gatir_testkit::origin::{MockOrigin, Reply};
use gatir_testkit::tcp::TcpServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

struct TestProxy {
    addr: SocketAddr,
    shutdown: CancellationToken,
    force: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl TestProxy {
    /// Waits up to `limit` for `Server::run` to return.
    async fn finished_within(&mut self, limit: Duration) -> bool {
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
async fn start_proxy(extra: &str) -> TestProxy {
    let toml = format!("listen = [\"127.0.0.1:0\"]\n{extra}");
    let config = Config::from_toml_str(&toml, Overrides::default()).expect("test configuration");
    let server = Server::bind(&config).await.expect("bind the proxy");
    let addr = server.local_addrs()[0];
    let shutdown = CancellationToken::new();
    let force = CancellationToken::new();
    let task = tokio::spawn(server.run(shutdown.clone(), force.clone()));
    TestProxy {
        addr,
        shutdown,
        force,
        task: Some(task),
    }
}

/// A proxy-style GET request (absolute-form target).
fn get(authority: &str, path: &str, extra_headers: &str) -> String {
    format!("GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\n{extra_headers}\r\n")
}

/// FNV-1a, to compare large bodies without keeping two copies around.
fn fnv(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn forwards_a_get_in_origin_form() {
    let origin = MockOrigin::start(|_| Reply::ok("hello")).await;
    let proxy = start_proxy("").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get(&origin.authority(), "/hello?x=1", ""))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body_text(), "hello");
    let seen = &origin.requests()[0];
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.target, "/hello?x=1");
    assert_eq!(seen.version, "HTTP/1.1");
    assert_eq!(seen.headers.get("host"), Some(origin.authority().as_str()));
}

#[tokio::test]
async fn a_client_connection_serves_many_requests_until_asked_to_close() {
    let origin = MockOrigin::start(|request| Reply::ok(&request.target)).await;
    let proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    for path in ["/one", "/two", "/three"] {
        client
            .send(get(&origin.authority(), path, ""))
            .await
            .unwrap();
        let response = client.read_response(false).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body_text(), path);
    }

    client
        .send(get(&origin.authority(), "/last", "Connection: close\r\n"))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();
    assert_eq!(response.body_text(), "/last");
    assert!(client.closed_within(Duration::from_secs(2)).await);
}

#[tokio::test]
async fn a_post_body_with_content_length_is_forwarded() {
    let origin =
        MockOrigin::start(|request| Reply::ok(&format!("got {}", request.body.len()))).await;
    let proxy = start_proxy("").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(format!(
            "POST http://{a}/submit HTTP/1.1\r\nHost: {a}\r\nContent-Length: 7\r\n\r\nabc=123",
            a = origin.authority()
        ))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.body_text(), "got 7");
    let seen = &origin.requests()[0];
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.body, b"abc=123");
    assert_eq!(seen.headers.get("content-length"), Some("7"));
}

#[tokio::test]
async fn a_chunked_request_body_reaches_the_origin_intact() {
    let origin = MockOrigin::start(|_| Reply::ok("done")).await;
    let proxy = start_proxy("").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(format!(
            "POST http://{a}/upload HTTP/1.1\r\nHost: {a}\r\nTransfer-Encoding: chunked\r\n\r\n\
             5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            a = origin.authority()
        ))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 200);
    let seen = &origin.requests()[0];
    assert_eq!(seen.body, b"hello world");
    assert!(
        seen.headers
            .get("transfer-encoding")
            .is_some_and(|v| v.contains("chunked"))
    );
    assert!(!seen.headers.contains("content-length"));
}

#[tokio::test]
async fn a_chunked_response_is_relayed_intact() {
    let origin = MockOrigin::start(|_| {
        Reply::raw(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
             5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
    })
    .await;
    let proxy = start_proxy("").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body_text(), "hello world");
}

#[tokio::test]
async fn a_head_response_has_no_body_and_leaves_the_connection_usable() {
    let origin = MockOrigin::start(|request| {
        if request.method == "HEAD" {
            // Announces a length but, as HEAD requires, sends no body.
            Reply::raw("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
        } else {
            Reply::ok("second")
        }
    })
    .await;
    let proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send(format!(
            "HEAD http://{a}/ HTTP/1.1\r\nHost: {a}\r\n\r\n",
            a = origin.authority()
        ))
        .await
        .unwrap();
    let head = client.read_response(true).await.unwrap();
    assert_eq!(head.status, 200);
    assert_eq!(head.headers.get("content-length"), Some("1234"));
    assert!(head.body.is_empty());

    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "second"
    );
}

#[tokio::test]
async fn hop_by_hop_headers_and_proxy_credentials_are_not_forwarded() {
    let origin = MockOrigin::start(|_| {
        Reply::raw(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: X-Resp\r\nX-Resp: 1\r\n\
             Keep-Alive: timeout=5\r\nX-Public: ok\r\n\r\nhi",
        )
    })
    .await;
    let proxy = start_proxy("").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get(
            &origin.authority(),
            "/",
            "Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic c2VjcmV0\r\n\
             Connection: X-Secret\r\nX-Secret: 1\r\nX-Keep: yes\r\n",
        ))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    let seen = &origin.requests()[0];
    for name in ["proxy-connection", "proxy-authorization", "x-secret"] {
        assert!(!seen.headers.contains(name), "{name} reached the origin");
    }
    assert_eq!(seen.headers.get("x-keep"), Some("yes"));

    for name in ["x-resp", "keep-alive"] {
        assert!(
            !response.headers.contains(name),
            "{name} reached the client"
        );
    }
    assert_eq!(response.headers.get("x-public"), Some("ok"));
}

#[tokio::test]
async fn an_unreachable_origin_gives_502() {
    let dead = closed_port().await;
    let proxy = start_proxy("").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(get(&dead.to_string(), "/", "")).await.unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 502);
    assert!(
        response.body_text().contains("Cannot connect to"),
        "{}",
        response.body_text()
    );

    // The client connection survives an origin failure.
    let origin = MockOrigin::start(|_| Reply::ok("alive")).await;
    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "alive"
    );
}

#[tokio::test]
async fn an_unresolvable_host_gives_a_gateway_error() {
    let proxy = start_proxy("[timeouts]\nconnect_secs = 3").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("no-such-host.invalid", "/", ""))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert!(
        response.status == 502 || response.status == 504,
        "unexpected status {}",
        response.status
    );
}

#[tokio::test]
async fn a_misbehaving_origin_does_not_take_the_proxy_down() {
    let broken = MockOrigin::start(|_| Reply::raw("this is not http\r\n\r\n").then_close()).await;
    let good = MockOrigin::start(|_| Reply::ok("fine")).await;
    let proxy = start_proxy("").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get(&broken.authority(), "/", ""))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 502);

    let mut second = RawClient::connect(proxy.addr).await.unwrap();
    second.send(get(&good.authority(), "/", "")).await.unwrap();
    assert_eq!(
        second.read_response(false).await.unwrap().body_text(),
        "fine"
    );
}

#[tokio::test]
async fn one_client_connection_can_reach_different_origins() {
    let first = MockOrigin::start(|_| Reply::ok("from first")).await;
    let second = MockOrigin::start(|_| Reply::ok("from second")).await;
    let proxy = start_proxy("").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    for (origin, expected) in [
        (&first, "from first"),
        (&second, "from second"),
        (&first, "from first"),
    ] {
        client
            .send(get(&origin.authority(), "/", ""))
            .await
            .unwrap();
        assert_eq!(
            client.read_response(false).await.unwrap().body_text(),
            expected
        );
    }
}

#[tokio::test]
async fn requests_that_are_not_in_absolute_form_are_rejected() {
    let proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 400);
    assert!(
        response.body_text().contains("absolute form"),
        "{}",
        response.body_text()
    );
    assert!(client.closed_within(Duration::from_secs(2)).await);
}

#[tokio::test]
async fn https_urls_in_plain_requests_are_rejected() {
    let proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send("GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 400);
    assert!(
        response.body_text().contains("CONNECT"),
        "{}",
        response.body_text()
    );
}

#[tokio::test]
async fn content_length_with_transfer_encoding_reaches_the_origin_unambiguously() {
    // RFC 9112 section 6.3: Transfer-Encoding wins and the received
    // Content-Length must be removed before forwarding, so the origin cannot
    // frame the message differently from the proxy (request smuggling).
    let origin = MockOrigin::start(|_| Reply::ok("done")).await;
    let proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send(format!(
            "POST http://{a}/ HTTP/1.1\r\nHost: {a}\r\nContent-Length: 4\r\n\
             Transfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
            a = origin.authority()
        ))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);

    let seen = &origin.requests()[0];
    assert_eq!(seen.body, b"abcd");
    assert!(
        !seen.headers.contains("content-length"),
        "ambiguous framing was forwarded"
    );
    assert!(
        seen.headers
            .get("transfer-encoding")
            .is_some_and(|v| v.contains("chunked"))
    );
}

#[tokio::test]
async fn clients_rejected_by_the_access_rules_get_403() {
    let origin = MockOrigin::start(|_| Reply::ok("secret")).await;
    let proxy = start_proxy("[access]\ndefault = \"deny\"").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 403);
    assert!(response.body_text().contains("Access denied"));
    assert!(client.closed_within(Duration::from_secs(2)).await);
    assert!(origin.requests().is_empty());
}

#[tokio::test]
async fn clients_allowed_by_the_access_rules_are_served() {
    let origin = MockOrigin::start(|_| Reply::ok("open")).await;
    let proxy =
        start_proxy("[access]\ndefault = \"deny\"\nrules = [{ allow = \"127.0.0.1\" }]").await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "open"
    );
}

#[tokio::test]
async fn large_bodies_stream_through_intact_in_both_directions() {
    const SIZE: usize = 32 * 1024 * 1024;

    let origin = MockOrigin::start(|request| {
        if request.method == "POST" {
            Reply::ok(&format!("{}:{}", request.body.len(), fnv(&request.body)))
        } else {
            let body = pattern(SIZE);
            let mut reply =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {SIZE}\r\n\r\n").into_bytes();
            reply.extend_from_slice(&body);
            Reply::raw(reply)
        }
    })
    .await;
    let proxy = start_proxy("").await;

    // Upload
    let upload = pattern(SIZE);
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(format!(
            "POST http://{a}/up HTTP/1.1\r\nHost: {a}\r\nContent-Length: {SIZE}\r\n\r\n",
            a = origin.authority()
        ))
        .await
        .unwrap();
    client.send(&upload).await.unwrap();
    let response = client.read_response(false).await.unwrap();
    assert_eq!(response.body_text(), format!("{SIZE}:{}", fnv(&upload)));

    // Download
    client
        .send(get(&origin.authority(), "/down", ""))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();
    assert_eq!(response.body.len(), SIZE);
    assert_eq!(fnv(&response.body), fnv(&pattern(SIZE)));
}

// ---- CONNECT tunnels ----

fn connect_request(authority: &str) -> String {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
}

/// Opens a tunnel to `authority` and returns the client, positioned right after
/// the `200` head.
async fn open_tunnel(proxy: &TestProxy, authority: &str) -> RawClient {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(connect_request(authority)).await.unwrap();
    let response = client.read_response(true).await.unwrap();
    assert_eq!(response.status, 200, "{}", response.body_text());
    client
}

/// A destination that sends back whatever it receives.
async fn echo_server() -> TcpServer {
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

async fn eventually(what: &str, condition: impl Fn() -> bool) {
    for _ in 0..50 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn connect_relays_bytes_in_both_directions() {
    let echo = echo_server().await;
    let proxy = start_proxy("").await;
    let mut client = open_tunnel(&proxy, &echo.authority()).await;

    for message in [
        "hello tunnel",
        "a second message",
        "\u{0}\u{1}\u{2} binary \u{ff}",
    ] {
        client.send(message).await.unwrap();
        let echoed = client.read_exact(message.len()).await.unwrap();
        assert_eq!(echoed, message.as_bytes());
    }
}

#[tokio::test]
async fn connect_relays_a_half_close() {
    // The destination only answers after the client says it is done sending.
    let server = TcpServer::start(|mut stream| async move {
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received).await;
        let _ = stream
            .write_all(format!("got:{}", received.len()).as_bytes())
            .await;
        let _ = stream.shutdown().await;
    })
    .await;
    let proxy = start_proxy("").await;
    let mut client = open_tunnel(&proxy, &server.authority()).await;

    client.send("hello").await.unwrap();
    client.shutdown_write().await.unwrap();
    assert_eq!(client.read_to_end().await.unwrap(), b"got:5");
}

#[tokio::test]
async fn connect_ends_when_the_destination_closes() {
    let server = TcpServer::start(|mut stream| async move {
        let _ = stream.write_all(b"bye").await;
        let _ = stream.shutdown().await;
    })
    .await;
    let proxy = start_proxy("").await;
    let mut client = open_tunnel(&proxy, &server.authority()).await;

    assert_eq!(client.read_to_end().await.unwrap(), b"bye");
}

#[tokio::test]
async fn connect_ends_when_the_client_closes() {
    let saw_eof = Arc::new(AtomicBool::new(false));
    let server = TcpServer::start({
        let saw_eof = saw_eof.clone();
        move |mut stream| {
            let saw_eof = saw_eof.clone();
            async move {
                let mut buffer = [0u8; 64];
                while matches!(stream.read(&mut buffer).await, Ok(n) if n > 0) {}
                saw_eof.store(true, Ordering::SeqCst);
            }
        }
    })
    .await;
    let proxy = start_proxy("").await;

    let client = open_tunnel(&proxy, &server.authority()).await;
    assert!(!saw_eof.load(Ordering::SeqCst));
    drop(client);
    eventually("the destination to see the client close", || {
        saw_eof.load(Ordering::SeqCst)
    })
    .await;
}

#[tokio::test]
async fn connect_to_an_unreachable_destination_gives_502() {
    let dead = closed_port().await;
    let proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send(connect_request(&dead.to_string()))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 502);
    assert!(response.body_text().contains("Cannot connect to"));
}

#[tokio::test]
async fn connect_without_a_port_is_rejected() {
    let proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client.send(connect_request("example.com")).await.unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 400);
    assert!(response.body_text().contains("host:port"));
}

#[tokio::test]
async fn an_idle_tunnel_is_closed() {
    let echo = echo_server().await;
    let proxy = start_proxy("[timeouts]\ntunnel_idle_secs = 1").await;
    let mut client = open_tunnel(&proxy, &echo.authority()).await;

    assert!(client.closed_within(Duration::from_secs(5)).await);
}

#[tokio::test]
async fn a_busy_tunnel_outlives_the_idle_timeout() {
    let echo = echo_server().await;
    let proxy = start_proxy("[timeouts]\ntunnel_idle_secs = 1").await;
    let mut client = open_tunnel(&proxy, &echo.authority()).await;

    // 2.4 seconds in total, but never silent for a full second.
    for round in 0..6 {
        client.send("x").await.unwrap();
        assert_eq!(client.read_exact(1).await.unwrap(), b"x", "round {round}");
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

#[tokio::test]
async fn many_tunnels_work_at_the_same_time() {
    let echo = echo_server().await;
    let proxy = start_proxy("").await;

    let mut tasks = Vec::new();
    for id in 0..25u8 {
        let authority = echo.authority();
        let proxy_addr = proxy.addr;
        tasks.push(tokio::spawn(async move {
            let mut client = RawClient::connect(proxy_addr).await.unwrap();
            client.send(connect_request(&authority)).await.unwrap();
            assert_eq!(client.read_response(true).await.unwrap().status, 200);

            let payload: Vec<u8> = (0..10_000).map(|i| (i as u8).wrapping_add(id)).collect();
            client.send(&payload).await.unwrap();
            assert_eq!(client.read_exact(payload.len()).await.unwrap(), payload);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn large_transfers_through_a_tunnel_are_intact() {
    const SIZE: usize = 16 * 1024 * 1024;

    // Download: the destination pushes a large body and closes.
    let source = TcpServer::start(|mut stream| async move {
        let _ = stream.write_all(&pattern(SIZE)).await;
        let _ = stream.shutdown().await;
    })
    .await;
    // Upload: the destination hashes everything it receives.
    let sink = TcpServer::start(|mut stream| async move {
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received).await;
        let _ = stream
            .write_all(format!("{}:{}", received.len(), fnv(&received)).as_bytes())
            .await;
        let _ = stream.shutdown().await;
    })
    .await;
    let proxy = start_proxy("").await;

    let mut downloader = open_tunnel(&proxy, &source.authority()).await;
    let downloaded = downloader.read_to_end().await.unwrap();
    assert_eq!(downloaded.len(), SIZE);
    assert_eq!(fnv(&downloaded), fnv(&pattern(SIZE)));

    let mut uploader = open_tunnel(&proxy, &sink.authority()).await;
    let upload = pattern(SIZE);
    uploader.send(&upload).await.unwrap();
    uploader.shutdown_write().await.unwrap();
    let reply = uploader.read_to_end().await.unwrap();
    assert_eq!(
        String::from_utf8(reply).unwrap(),
        format!("{SIZE}:{}", fnv(&upload))
    );
}

#[tokio::test]
async fn a_tunnel_can_follow_plain_requests_on_the_same_connection() {
    let origin = MockOrigin::start(|_| Reply::ok("plain")).await;
    let echo = echo_server().await;
    let proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "plain"
    );

    client
        .send(connect_request(&echo.authority()))
        .await
        .unwrap();
    assert_eq!(client.read_response(true).await.unwrap().status, 200);
    client.send("after").await.unwrap();
    assert_eq!(client.read_exact(5).await.unwrap(), b"after");
}

// ---- client timeouts, request limits and shutdown ----

#[tokio::test]
async fn a_silent_client_connection_is_closed_after_the_idle_timeout() {
    let proxy = start_proxy("[timeouts]\nclient_idle_secs = 1").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    let started = std::time::Instant::now();
    assert!(client.read_to_end().await.unwrap().is_empty());
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(900),
        "closed too early: {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(5),
        "closed too late: {waited:?}"
    );
}

#[tokio::test]
async fn a_client_connection_is_closed_when_idle_between_requests() {
    let origin = MockOrigin::start(|_| Reply::ok("hi")).await;
    let proxy = start_proxy("[timeouts]\nclient_idle_secs = 1").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().body_text(), "hi");

    let started = std::time::Instant::now();
    assert!(client.read_to_end().await.unwrap().is_empty());
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn a_request_head_that_never_completes_is_dropped() {
    let proxy = start_proxy("[timeouts]\nclient_idle_secs = 1").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    // No blank line ends the header section.
    client
        .send("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n")
        .await
        .unwrap();

    let started = std::time::Instant::now();
    let _ = client.read_to_end().await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// The proxy must answer 431 or, when it gives up mid-upload, just close.
async fn assert_refused(client: &mut RawClient) {
    if let Ok(response) = client.read_response(false).await {
        assert_eq!(response.status, 431);
    }
}

#[tokio::test]
async fn large_but_reasonable_request_heads_are_forwarded() {
    let origin = MockOrigin::start(|_| Reply::ok("ok")).await;
    let proxy = start_proxy("").await;

    // Big cookies are common in practice.
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    let cookie = format!("Cookie: {}\r\n", "c".repeat(50 * 1024));
    client
        .send(get(&origin.authority(), "/", &cookie))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);

    // Close to the field-count limit.
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    let fields: String = (0..90).map(|i| format!("X-{i}: v\r\n")).collect();
    client
        .send(get(&origin.authority(), "/", &fields))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);
}

#[tokio::test]
async fn oversized_request_heads_are_refused() {
    let origin = MockOrigin::start(|_| Reply::ok("must not be reached")).await;
    let proxy = start_proxy("").await;

    // Header fields larger than the limit, just over it and far over it. The
    // proxy may close while we are still sending.
    for size in [70 * 1024, 100 * 1024, 1024 * 1024] {
        let mut client = RawClient::connect(proxy.addr).await.unwrap();
        let big = format!("X-Big: {}\r\n", "a".repeat(size));
        let _ = client.send(get(&origin.authority(), "/", &big)).await;
        assert_refused(&mut client).await;
    }

    // Too many header fields.
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    let many: String = (0..150).map(|i| format!("X-{i}: v\r\n")).collect();
    let _ = client.send(get(&origin.authority(), "/", &many)).await;
    assert_refused(&mut client).await;

    assert!(
        origin.requests().is_empty(),
        "the origin saw an oversized request"
    );
}

#[tokio::test]
async fn shutdown_lets_an_active_request_finish_then_closes_the_connection() {
    let origin = MockOrigin::start(|_| Reply::ok("late").after(Duration::from_millis(600))).await;
    let mut proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    eventually("the origin to receive the request", || {
        !origin.requests().is_empty()
    })
    .await;

    proxy.shutdown.cancel();
    let response = client.read_response(false).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body_text(), "late");
    assert!(client.closed_within(Duration::from_secs(2)).await);
    assert!(proxy.finished_within(Duration::from_secs(2)).await);
}

#[tokio::test]
async fn shutdown_closes_idle_keep_alive_connections_at_once() {
    let origin = MockOrigin::start(|_| Reply::ok("hi")).await;
    let mut proxy = start_proxy("").await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);

    proxy.shutdown.cancel();
    assert!(client.closed_within(Duration::from_secs(2)).await);
    assert!(proxy.finished_within(Duration::from_secs(2)).await);
}

#[tokio::test]
async fn shutdown_stops_accepting_connections() {
    let mut proxy = start_proxy("").await;
    proxy.shutdown.cancel();

    assert!(proxy.finished_within(Duration::from_secs(2)).await);
    assert!(tokio::net::TcpStream::connect(proxy.addr).await.is_err());
}

#[tokio::test]
async fn shutdown_lets_a_tunnel_run_until_the_grace_period_ends() {
    let echo = echo_server().await;
    let mut proxy = start_proxy("[timeouts]\nshutdown_grace_secs = 1").await;
    let mut client = open_tunnel(&proxy, &echo.authority()).await;

    proxy.shutdown.cancel();

    // The tunnel keeps working during the grace period...
    client.send("still here").await.unwrap();
    assert_eq!(client.read_exact(10).await.unwrap(), b"still here");
    assert!(!proxy.finished_within(Duration::from_millis(200)).await);

    // ...and is closed when the period ends.
    assert!(proxy.finished_within(Duration::from_secs(4)).await);
    assert!(client.closed_within(Duration::from_secs(2)).await);
}

#[tokio::test]
async fn a_second_interrupt_closes_everything_at_once() {
    let echo = echo_server().await;
    let mut proxy = start_proxy("[timeouts]\nshutdown_grace_secs = 30").await;
    let mut client = open_tunnel(&proxy, &echo.authority()).await;

    proxy.shutdown.cancel();
    assert!(!proxy.finished_within(Duration::from_millis(200)).await);

    proxy.force.cancel();
    assert!(proxy.finished_within(Duration::from_secs(2)).await);
    assert!(client.closed_within(Duration::from_secs(2)).await);
}
