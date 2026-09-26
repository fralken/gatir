//! Negotiate (Kerberos) authentication to a parent proxy. There is no Kerberos
//! ticket here, so the tokens come from a stand-in that writes the service it
//! was asked for into the token, and the mock parent accepts one exact token.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use gatir::auth::{AuthError, TokenSource};
use gatir_testkit::http::{RawClient, Response};
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};

/// Tokens that name the service they are for.
#[derive(Debug)]
struct Tickets;

impl TokenSource for Tickets {
    fn token(&self, service: &str) -> Result<Vec<u8>, AuthError> {
        Ok(format!("ticket for {service}").into_bytes())
    }
}

/// A user with no ticket.
#[derive(Debug)]
struct NoTickets;

impl TokenSource for NoTickets {
    fn token(&self, service: &str) -> Result<Vec<u8>, AuthError> {
        Err(AuthError::NoTicket {
            service: service.to_owned(),
            reason: "No Kerberos credentials available".to_owned(),
        })
    }
}

/// A KDC that does not answer.
#[derive(Debug)]
struct SlowKdc;

impl TokenSource for SlowKdc {
    fn token(&self, _service: &str) -> Result<Vec<u8>, AuthError> {
        std::thread::sleep(Duration::from_secs(4));
        Ok(b"too late".to_vec())
    }
}

fn accepting(token: &str) -> Options {
    Options {
        offers: vec!["Negotiate".to_owned(), "NTLM".to_owned()],
        negotiate_token: Some(token.as_bytes().to_vec()),
        ..Options::default()
    }
}

async fn parent_with(options: Options) -> MockNtlmParent {
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

/// The configuration of a proxy that uses Negotiate to reach `parent`.
fn config(parent: &MockNtlmParent) -> String {
    format!(
        "parents = [\"{}\"]\n[credentials]\nmethod = \"negotiate\"\n",
        parent.addr()
    )
}

async fn proxy_for(parent: &MockNtlmParent) -> TestProxy {
    start_proxy_with_tokens(&config(parent), Arc::new(Tickets)).await
}

async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>) -> Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

#[tokio::test]
async fn a_request_carries_the_ticket_and_needs_no_probe_or_challenge() {
    let parent = parent_with(accepting("ticket for HTTP@127.0.0.1")).await;
    let proxy = proxy_for(&parent).await;

    let response = ask(
        &proxy,
        get("origin.example.com", "/page", "X-Keep: yes\r\n"),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(response.body_text(), "GET 0 bytes");

    // One request, with the proof in it: nothing was sent to get a challenge.
    let seen = parent.requests();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].served);
    assert_eq!(
        seen[0].negotiate.as_deref(),
        Some(b"ticket for HTTP@127.0.0.1".as_slice())
    );
    assert_eq!(seen[0].request.target, "http://origin.example.com/page");
    assert_eq!(seen[0].request.headers.get("x-keep"), Some("yes"));
}

#[tokio::test]
async fn the_configured_service_name_is_used() {
    let parent = parent_with(accepting("ticket for HTTP/proxy.example.com@EXAMPLE.COM")).await;
    let proxy = start_proxy_with_tokens(
        &format!(
            "parents = [\"{}\"]\n[credentials]\nmethod = \"negotiate\"\n\
             spn = \"HTTP/proxy.example.com@EXAMPLE.COM\"\n",
            parent.addr()
        ),
        Arc::new(Tickets),
    )
    .await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 200, "{}", response.body_text());
}

#[tokio::test]
async fn a_post_goes_once_with_its_body_and_the_ticket() {
    let parent = parent_with(accepting("ticket for HTTP@127.0.0.1")).await;
    let proxy = proxy_for(&parent).await;

    let response = ask(
        &proxy,
        "POST http://origin.example.com/up HTTP/1.1\r\nHost: origin.example.com\r\n\
         Content-Length: 5\r\n\r\nhello",
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(response.body_text(), "POST 5 bytes");

    // No probe: the only request is the client's own.
    let seen = parent.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].request.method, "POST");
    assert_eq!(seen[0].request.body, b"hello");
    assert!(seen[0].negotiate.is_some());
}

#[tokio::test]
async fn a_head_needs_no_probe_either() {
    let parent = parent_with(accepting("ticket for HTTP@127.0.0.1")).await;
    let proxy = proxy_for(&parent).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send("HEAD http://origin.example.com/ HTTP/1.1\r\nHost: origin.example.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(client.read_response(true).await.unwrap().status, 200);
    assert_eq!(parent.requests().len(), 1);
    assert_eq!(parent.requests()[0].request.method, "HEAD");
}

#[tokio::test]
async fn an_authenticated_connection_is_reused_without_another_ticket() {
    let parent = parent_with(accepting("ticket for HTTP@127.0.0.1")).await;
    let proxy = proxy_for(&parent).await;

    for path in ["/one", "/two", "/three"] {
        assert_eq!(
            ask(&proxy, get("origin.example.com", path, ""))
                .await
                .status,
            200
        );
    }

    assert_eq!(parent.connection_count(), 1);
    let seen = parent.requests();
    assert_eq!(seen.len(), 3);
    assert!(seen[0].negotiate.is_some());
    assert!(seen[1].negotiate.is_none() && seen[2].negotiate.is_none());
}

#[tokio::test]
async fn a_tunnel_opens_with_one_connect_carrying_the_ticket() {
    let parent = parent_with(accepting("ticket for HTTP@127.0.0.1")).await;
    let proxy = proxy_for(&parent).await;

    let mut client = open_tunnel(&proxy, "example.com:443").await;
    client.send("through the tunnel").await.unwrap();
    assert_eq!(client.read_exact(18).await.unwrap(), b"through the tunnel");

    let seen = parent.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].request.method, "CONNECT");
    assert!(seen[0].negotiate.is_some());
}

#[tokio::test]
async fn a_connection_that_loses_its_authentication_is_replaced() {
    let parent = parent_with(Options {
        forget_after: Some(1),
        ..accepting("ticket for HTTP@127.0.0.1")
    })
    .await;
    let proxy = proxy_for(&parent).await;

    assert_eq!(
        ask(&proxy, get("origin.example.com", "/one", ""))
            .await
            .status,
        200
    );
    let second = ask(&proxy, get("origin.example.com", "/two", "")).await;
    assert_eq!(second.status, 200, "{}", second.body_text());

    assert_eq!(parent.connection_count(), 2);
    assert_eq!(parent.served().len(), 2);
    assert_eq!(
        parent
            .requests()
            .iter()
            .filter(|seen| seen.negotiate.is_some())
            .count(),
        2
    );
}

#[tokio::test]
async fn parallel_requests_all_get_through() {
    let parent = parent_with(accepting("ticket for HTTP@127.0.0.1")).await;
    let proxy = proxy_for(&parent).await;

    let mut tasks = Vec::new();
    for index in 0..8 {
        let addr = proxy.addr;
        tasks.push(tokio::spawn(async move {
            let mut client = RawClient::connect(addr).await.unwrap();
            client
                .send(get("origin.example.com", &format!("/{index}"), ""))
                .await
                .unwrap();
            client.read_response(false).await.unwrap().status
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 200);
    }
    let proofs = parent
        .requests()
        .iter()
        .filter(|seen| seen.negotiate.is_some())
        .count();
    assert_eq!(proofs, parent.connection_count());
}

#[tokio::test]
async fn a_ticket_the_parent_refuses_is_reported_and_asked_for_again() {
    let parent = parent_with(accepting("a different ticket")).await;
    let proxy = proxy_for(&parent).await;

    for _ in 0..2 {
        let response = ask(&proxy, get("origin.example.com", "/", "")).await;
        assert_eq!(response.status, 502);
        assert!(
            response
                .body_text()
                .contains("did not accept the Kerberos ticket for HTTP@127.0.0.1"),
            "{}",
            response.body_text()
        );
    }
    // Nothing here can lock an account, so there is no pause: both were tried.
    assert_eq!(parent.requests().len(), 2);
}

#[tokio::test]
async fn a_parent_without_negotiate_is_reported_with_the_schemes_it_offers() {
    let parent = parent_with(Options::default()).await;
    let proxy = proxy_for(&parent).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("does not offer Negotiate authentication (it offers: NTLM)"),
        "{}",
        response.body_text()
    );
}

#[tokio::test]
async fn without_a_ticket_no_request_is_sent() {
    let parent = parent_with(accepting("ticket for HTTP@127.0.0.1")).await;
    let proxy = start_proxy_with_tokens(&config(&parent), Arc::new(NoTickets)).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("cannot get a Kerberos ticket for HTTP@127.0.0.1: No Kerberos credentials"),
        "{}",
        response.body_text()
    );
    assert!(parent.requests().is_empty());
}

#[tokio::test]
async fn a_kdc_that_does_not_answer_gives_a_gateway_timeout() {
    let parent = parent_with(accepting("ticket for HTTP@127.0.0.1")).await;
    let proxy = start_proxy_with_tokens(
        &format!("{}[timeouts]\nresponse_secs = 1\n", config(&parent)),
        Arc::new(SlowKdc),
    )
    .await;

    let started = Instant::now();
    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 504);
    assert!(
        response.body_text().contains("Kerberos server"),
        "{}",
        response.body_text()
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn destinations_reached_directly_get_no_ticket() {
    let parent = parent_with(accepting("ticket for HTTP@127.0.0.1")).await;
    let origin = MockOrigin::start(|_| Reply::ok("direct")).await;
    let proxy = start_proxy_with_tokens(
        &format!(
            "parents = [\"{}\"]\nno_proxy = [\"127.0.0.1\"]\n[credentials]\nmethod = \"negotiate\"\n",
            parent.addr()
        ),
        Arc::new(Tickets),
    )
    .await;

    let response = ask(&proxy, get(&origin.authority(), "/", "")).await;
    assert_eq!(response.body_text(), "direct");
    assert!(!origin.requests()[0].headers.contains("proxy-authorization"));
    assert!(parent.requests().is_empty());
}
