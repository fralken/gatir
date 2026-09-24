//! End-to-end tests of the proxy against a scripted origin server.
//!
//! Clients and origins speak raw bytes through `gatir-testkit`, which parses
//! HTTP by hand, so these tests do not depend on the HTTP library the proxy
//! is built on.

use std::net::SocketAddr;
use std::time::Duration;

use gatir::config::{Config, Overrides};
use gatir::proxy::Server;
use gatir_testkit::closed_port;
use gatir_testkit::http::RawClient;
use gatir_testkit::origin::{MockOrigin, Reply};
use tokio_util::sync::CancellationToken;

struct TestProxy {
    addr: SocketAddr,
    shutdown: CancellationToken,
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
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
    tokio::spawn(server.run(shutdown.clone()));
    TestProxy { addr, shutdown }
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
