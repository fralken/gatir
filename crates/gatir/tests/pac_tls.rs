//! A PAC script fetched over https: the certificate is checked by the
//! operating system against the authorities it trusts, and against the name in
//! the address. The servers are rustls, with certificates made for each test.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use gatir::pac::{FetchError, Fetched, Trust, Validators, fetch};
use gatir_testkit::http::RawClient;
use gatir_testkit::origin::{MockOrigin, Reply};
use gatir_testkit::tcp::TcpServer;
use gatir_testkit::tls::{Identity, TestCa};

const LIMIT: Duration = Duration::from_secs(10);
const SCRIPT: &str = r#"function FindProxyForURL(url, host) { return "DIRECT"; }"#;

fn serving(
    script: &str,
) -> impl Fn(&gatir_testkit::http::Request) -> Reply + Send + Sync + 'static {
    let reply = Reply::ok(script);
    move |_| reply.clone()
}

fn https(host: &str, origin: &MockOrigin, path: &str) -> String {
    format!("https://{host}:{}{path}", origin.addr().port())
}

async fn fetched(address: &str, trust: &Trust) -> Result<Fetched, FetchError> {
    fetch(address, LIMIT, &Validators::default(), trust).await
}

fn script_of(result: Result<Fetched, FetchError>) -> String {
    match result {
        Ok(Fetched::Script { bytes, .. }) => String::from_utf8(bytes).unwrap(),
        other => panic!("expected a script, got {other:?}"),
    }
}

#[tokio::test]
async fn a_script_is_fetched_from_a_server_whose_certificate_is_trusted() {
    let ca = TestCa::new("gatir test authority");
    let origin =
        MockOrigin::start_tls(&ca.server(&["localhost", "127.0.0.1"]), serving(SCRIPT)).await;
    let trust = Trust::system_and(ca.pem().as_bytes());

    let script = script_of(fetched(&https("localhost", &origin, "/proxy.pac"), &trust).await);
    assert_eq!(script, SCRIPT);
    // The server is told which name the client wants (SNI)...
    assert_eq!(origin.server_names(), [Some("localhost".to_owned())]);

    // ...and, for an address, there is no name to tell, but the certificate is
    // still checked against the address.
    let script = script_of(fetched(&https("127.0.0.1", &origin, "/proxy.pac"), &trust).await);
    assert_eq!(script, SCRIPT);
    assert_eq!(origin.server_names()[1], None);
    assert_eq!(origin.requests().len(), 2);
}

#[tokio::test]
async fn a_certificate_that_does_not_check_out_is_refused_before_anything_is_sent() {
    let ca = TestCa::new("gatir test authority");
    let rogue = TestCa::new("someone else");
    let ours = Trust::system_and(ca.pem().as_bytes());

    struct Case {
        what: &'static str,
        identity: Identity,
        host: &'static str,
        trust: Trust,
    }
    let cases = [
        Case {
            what: "an authority nobody told the system about",
            identity: ca.server(&["localhost"]),
            host: "localhost",
            trust: Trust::system(),
        },
        Case {
            what: "a certificate for another name",
            identity: ca.server(&["other.example"]),
            host: "localhost",
            trust: ours.clone(),
        },
        Case {
            what: "an address the certificate does not cover",
            identity: ca.server(&["localhost"]),
            host: "127.0.0.1",
            trust: ours.clone(),
        },
        Case {
            what: "an expired certificate",
            identity: ca.expired_server(&["localhost", "127.0.0.1"]),
            host: "localhost",
            trust: ours.clone(),
        },
        Case {
            what: "a certificate from an authority that is not the trusted one",
            identity: rogue.server(&["localhost", "127.0.0.1"]),
            host: "localhost",
            trust: ours.clone(),
        },
    ];

    for case in cases {
        let origin = MockOrigin::start_tls(&case.identity, serving(SCRIPT)).await;
        let result = fetched(&https(case.host, &origin, "/proxy.pac"), &case.trust).await;
        match result {
            Err(FetchError::Tls { host, .. }) => assert_eq!(host, case.host, "{}", case.what),
            other => panic!("{}: expected a TLS failure, got {other:?}", case.what),
        }
        assert!(origin.requests().is_empty(), "{}", case.what);
    }
}

#[tokio::test]
async fn a_redirect_may_go_to_https_but_never_back_to_http() {
    let ca = TestCa::new("gatir test authority");
    let trust = Trust::system_and(ca.pem().as_bytes());
    let secure = MockOrigin::start_tls(&ca.server(&["localhost"]), serving(SCRIPT)).await;
    let plain = MockOrigin::start(serving(SCRIPT)).await;

    // http -> https is fine.
    let target = https("localhost", &secure, "/proxy.pac");
    let up = MockOrigin::start(move |_| {
        Reply::raw(format!(
            "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\n\r\n"
        ))
    })
    .await;
    let script = script_of(fetched(&format!("http://{}/p", up.authority()), &trust).await);
    assert_eq!(script, SCRIPT);

    // https -> http is not: what came over a secured connection is not to be
    // followed onto one that is not.
    let target = format!("http://{}/proxy.pac?token=hush", plain.authority());
    let down = MockOrigin::start_tls(&ca.server(&["localhost"]), move |_| {
        Reply::raw(format!(
            "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\n\r\n"
        ))
    })
    .await;
    let error = fetched(&https("localhost", &down, "/p"), &trust)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::Downgrade(_)), "{error}");
    assert!(!error.to_string().contains("hush"), "{error}");
    assert!(plain.requests().is_empty(), "nothing was sent in the clear");
}

#[tokio::test]
async fn a_server_that_does_not_speak_tls_or_does_not_answer_is_an_error() {
    let ca = TestCa::new("gatir test authority");
    let trust = Trust::system_and(ca.pem().as_bytes());

    // A plain server where https was expected.
    let plain = MockOrigin::start(serving(SCRIPT)).await;
    let result = fetched(&https("localhost", &plain, "/p"), &trust).await;
    assert!(result.is_err(), "{result:?}");
    assert!(plain.requests().is_empty());

    // A TLS server where http was expected.
    let secure = MockOrigin::start_tls(&ca.server(&["localhost"]), serving(SCRIPT)).await;
    let result = fetched(&format!("http://{}/p", secure.authority()), &trust).await;
    assert!(result.is_err(), "{result:?}");
    assert!(secure.requests().is_empty());

    // A server that accepts the connection and then says nothing: the time
    // limit covers the handshake too.
    let silent = TcpServer::start(|stream| async move {
        let _held = stream;
        tokio::time::sleep(Duration::from_secs(30)).await;
    })
    .await;
    let result = fetch(
        &format!("https://localhost:{}/p", silent.addr().port()),
        Duration::from_millis(500),
        &Validators::default(),
        &trust,
    )
    .await;
    assert!(matches!(result, Err(FetchError::Timeout(_))), "{result:?}");
}

#[tokio::test]
async fn an_error_message_says_what_to_check() {
    let ca = TestCa::new("gatir test authority");
    let origin = MockOrigin::start_tls(&ca.server(&["localhost"]), serving(SCRIPT)).await;
    let error = fetched(
        &format!("https://localhost:{}/p?token=hush", origin.addr().port()),
        &Trust::system(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.starts_with("TLS with localhost failed"), "{error}");
    assert!(error.contains("an authority this system trusts"), "{error}");
    assert!(!error.contains("hush"), "{error}");
}

/// A proxy that takes its script from https, and the script it took.
async fn proxy_for(address: &str, extra: &str, trust: Trust) -> TestProxy {
    start_proxy_trusting(&format!("[pac]\nurl = {address:?}\n{extra}"), trust).await
}

async fn through(proxy: &TestProxy) -> String {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(get("site.test", "/", "")).await.unwrap();
    client.read_response(false).await.unwrap().body_text()
}

fn choosing(parent: SocketAddr) -> String {
    format!(r#"function FindProxyForURL(url, host) {{ return "PROXY {parent}"; }}"#)
}

#[tokio::test]
async fn the_proxy_uses_and_refreshes_a_script_fetched_over_tls() {
    let (a, b) = (
        MockOrigin::start(|_| Reply::ok("A")).await,
        MockOrigin::start(|_| Reply::ok("B")).await,
    );
    let ca = TestCa::new("gatir test authority");
    let script = Arc::new(Mutex::new(choosing(a.addr())));
    let origin = MockOrigin::start_tls(&ca.server(&["localhost"]), {
        let script = script.clone();
        move |_| Reply::ok(&script.lock().unwrap())
    })
    .await;
    let address = https("localhost", &origin, "/proxy.pac");

    let proxy = proxy_for(
        &address,
        "refresh_secs = 1\n",
        Trust::system_and(ca.pem().as_bytes()),
    )
    .await;
    assert_eq!(through(&proxy).await, "A");

    *script.lock().unwrap() = choosing(b.addr());
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while through(&proxy).await != "B" {
        assert!(
            std::time::Instant::now() < deadline,
            "the new script never came"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_script_from_an_untrusted_server_is_never_used() {
    let ca = TestCa::new("gatir test authority");
    let origin = MockOrigin::start_tls(&ca.server(&["localhost"]), serving(SCRIPT)).await;
    let proxy = proxy_for(
        &https("localhost", &origin, "/proxy.pac"),
        "",
        Trust::system(),
    )
    .await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(get("site.test", "/", "")).await.unwrap();
    let response = client.read_response(false).await.unwrap();
    assert_eq!(response.status, 502);
    let text = response.body_text();
    assert!(text.contains("TLS with localhost failed"), "{text}");
    assert!(text.contains("keeps trying"), "{text}");
    assert!(origin.requests().is_empty());
}
