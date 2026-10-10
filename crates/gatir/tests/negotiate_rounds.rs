//! Negotiate when the system falls back to NTLM, as Windows does when Kerberos
//! is not possible: the first token is answered with a `407` and a token of the
//! parent's own, and the second token, on the same connection, authenticates.
//! The system is a stand-in that makes the tokens, and the parent is a mock.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use gatir::auth::{AuthError, SecurityContext, Step, TokenSource};
use gatir_testkit::http::{RawClient, Response};
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, NegotiateExchange, Options};
use gatir_testkit::origin::Reply;

const FIRST: &[u8] = b"first for HTTP@127.0.0.1";
const CHALLENGE: &[u8] = b"the parent's own token";
const SECOND: &[u8] = b"second for HTTP@127.0.0.1";

/// A system that needs two rounds, and remembers what the parent sent it.
#[derive(Debug, Default)]
struct TwoRounds {
    heard: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Fail the second round with this.
    fails_with: Option<&'static str>,
}

#[derive(Debug)]
struct Round {
    service: String,
    heard: Arc<Mutex<Vec<Vec<u8>>>>,
    fails_with: Option<&'static str>,
}

impl TokenSource for TwoRounds {
    fn start(&self, service: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
        Ok(Box::new(Round {
            service: service.to_owned(),
            heard: self.heard.clone(),
            fails_with: self.fails_with,
        }))
    }
}

impl SecurityContext for Round {
    fn step(&mut self, from_parent: Option<&[u8]>) -> Result<Step, AuthError> {
        match from_parent {
            None => Ok(Step {
                token: Some(format!("first for {}", self.service).into_bytes()),
                complete: false,
            }),
            Some(_) if self.fails_with.is_some() => Err(AuthError::Exchange {
                service: self.service.clone(),
                reason: self.fails_with.unwrap_or_default().to_owned(),
            }),
            Some(token) => {
                self.heard.lock().unwrap().push(token.to_vec());
                Ok(Step {
                    token: Some(format!("second for {}", self.service).into_bytes()),
                    complete: true,
                })
            }
        }
    }
}

fn exchange() -> Options {
    Options {
        offers: vec!["Negotiate".to_owned(), "NTLM".to_owned()],
        negotiate_exchange: Some(NegotiateExchange {
            first: FIRST.to_vec(),
            challenge: CHALLENGE.to_vec(),
            second: SECOND.to_vec(),
        }),
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

async fn proxy_with(parent: &MockNtlmParent, source: TwoRounds) -> TestProxy {
    start_proxy_with_tokens(
        &format!(
            "parents = [\"{}\"]\n[credentials]\nmethod = \"negotiate\"\n",
            parent.addr()
        ),
        Arc::new(source),
    )
    .await
}

async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>, head: bool) -> Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(head).await.unwrap()
}

#[tokio::test]
async fn a_get_opens_bare_then_carries_the_first_token_and_then_the_second() {
    let parent = parent_with(exchange()).await;
    let source = TwoRounds::default();
    let heard = source.heard.clone();
    let proxy = proxy_with(&parent, source).await;

    let response = ask(&proxy, get("origin.example.com", "/page", ""), false).await;
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(response.body_text(), "GET 0 bytes");

    // A bare probe opens the exchange; the request then carries the first
    // token, and is sent again with the second.
    let seen = parent.requests();
    assert_eq!(seen.len(), 3);
    assert!(seen[0].negotiate.is_none() && !seen[0].served);
    assert_eq!(seen[1].negotiate.as_deref(), Some(FIRST));
    assert!(!seen[1].served);
    assert_eq!(seen[2].negotiate.as_deref(), Some(SECOND));
    assert!(seen[2].served);
    assert!(seen.iter().all(|s| s.connection == seen[0].connection));
    assert!(
        seen.iter()
            .all(|s| s.request.target == "http://origin.example.com/page")
    );
    // The system was given what the parent sent, exactly.
    assert_eq!(*heard.lock().unwrap(), [CHALLENGE.to_vec()]);
}

#[tokio::test]
async fn a_post_is_sent_only_once_the_exchange_is_done() {
    let parent = parent_with(exchange()).await;
    let proxy = proxy_with(&parent, TwoRounds::default()).await;

    let response = ask(
        &proxy,
        "POST http://origin.example.com/up HTTP/1.1\r\nHost: origin.example.com\r\n\
         Content-Length: 5\r\n\r\nhello",
        false,
    )
    .await;
    assert_eq!(response.body_text(), "POST 5 bytes");

    // A bare probe, then one with the first token, open the exchange; the
    // second token goes with the real request, and never the method of the
    // request, so that nothing is done twice.
    let seen = parent.requests();
    let methods: Vec<&str> = seen.iter().map(|s| s.request.method.as_str()).collect();
    assert_eq!(methods, ["GET", "GET", "POST"]);
    assert!(seen[0].negotiate.is_none());
    assert_eq!(seen[1].negotiate.as_deref(), Some(FIRST));
    assert!(seen[0].request.body.is_empty() && seen[1].request.body.is_empty());
    assert_eq!(seen[2].negotiate.as_deref(), Some(SECOND));
    assert_eq!(seen[2].request.body, b"hello");
    assert!(seen[2].served);
}

#[tokio::test]
async fn a_head_is_opened_with_a_probe_too() {
    let parent = parent_with(exchange()).await;
    let proxy = proxy_with(&parent, TwoRounds::default()).await;
    let response = ask(
        &proxy,
        "HEAD http://origin.example.com/ HTTP/1.1\r\nHost: origin.example.com\r\n\r\n",
        true,
    )
    .await;
    assert_eq!(response.status, 200);
    let methods: Vec<String> = parent
        .requests()
        .iter()
        .map(|s| s.request.method.clone())
        .collect();
    assert_eq!(methods, ["GET", "GET", "HEAD"]);
}

#[tokio::test]
async fn a_tunnel_is_authenticated_in_two_rounds() {
    let parent = parent_with(exchange()).await;
    let proxy = proxy_with(&parent, TwoRounds::default()).await;

    let mut client = open_tunnel(&proxy, "example.com:443").await;
    client.send("through the tunnel").await.unwrap();
    assert_eq!(client.read_exact(18).await.unwrap(), b"through the tunnel");

    let seen = parent.requests();
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter()
            .all(|s| s.request.method == "CONNECT" && s.request.target == "example.com:443")
    );
    assert!(seen[0].negotiate.is_none());
    assert_eq!(seen[1].negotiate.as_deref(), Some(FIRST));
    assert_eq!(seen[2].negotiate.as_deref(), Some(SECOND));
    assert!(seen.iter().all(|s| s.connection == seen[0].connection));
}

#[tokio::test]
async fn the_connection_stays_authenticated_for_the_requests_after() {
    let parent = parent_with(exchange()).await;
    let proxy = proxy_with(&parent, TwoRounds::default()).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    for path in ["/one", "/two", "/three"] {
        client
            .send(get("origin.example.com", path, ""))
            .await
            .unwrap();
        assert_eq!(client.read_response(false).await.unwrap().status, 200);
    }
    // One connection to the parent, authenticated once: three requests were
    // served, the first of them after the exchange.
    assert_eq!(parent.connection_count(), 1);
    let seen = parent.requests();
    assert_eq!(seen.len(), 5);
    assert_eq!(seen.iter().filter(|s| s.negotiate.is_some()).count(), 2);
    assert_eq!(seen.iter().filter(|s| s.served).count(), 3);
}

#[tokio::test]
async fn a_parent_that_accepts_the_first_token_needs_no_second_round() {
    // The system asks for another round, and the parent has no use for it.
    let parent = parent_with(Options {
        offers: vec!["Negotiate".to_owned()],
        negotiate_token: Some(FIRST.to_vec()),
        ..Options::default()
    })
    .await;
    let proxy = proxy_with(&parent, TwoRounds::default()).await;

    let response = ask(&proxy, get("origin.example.com", "/", ""), false).await;
    assert_eq!(response.body_text(), "GET 0 bytes");
    // A bare probe, then the same request again with the token: nothing more
    // is needed once the parent takes it.
    assert_eq!(parent.requests().len(), 2);

    // With a body, the probes are answered, and the request follows on the
    // connection that they authenticated.
    let response = ask(
        &proxy,
        "POST http://origin.example.com/up HTTP/1.1\r\nHost: origin.example.com\r\n\
         Content-Length: 5\r\n\r\nhello",
        false,
    )
    .await;
    assert_eq!(response.body_text(), "POST 5 bytes");
    let seen = parent.requests();
    let posts: Vec<_> = seen.iter().filter(|s| s.request.method == "POST").collect();
    assert_eq!(posts.len(), 1, "the body goes once");
    assert!(posts[0].served && posts[0].negotiate.is_none());
}

#[tokio::test]
async fn a_parent_that_refuses_or_does_not_offer_negotiate_is_reported() {
    // It offers Negotiate and does not accept the token.
    let parent = parent_with(Options {
        offers: vec!["Negotiate".to_owned()],
        ..Options::default()
    })
    .await;
    let proxy = proxy_with(&parent, TwoRounds::default()).await;
    let response = ask(&proxy, get("origin.example.com", "/", ""), false).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("did not accept the Kerberos ticket for HTTP@127.0.0.1"),
        "{}",
        response.body_text()
    );

    // It offers something else.
    let parent = parent_with(Options {
        offers: vec!["Basic realm=\"x\"".to_owned()],
        ..Options::default()
    })
    .await;
    let proxy = proxy_with(&parent, TwoRounds::default()).await;
    let response = ask(&proxy, get("origin.example.com", "/", ""), false).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("does not offer Negotiate authentication (it offers: Basic)"),
        "{}",
        response.body_text()
    );
}

#[tokio::test]
async fn a_system_that_cannot_answer_the_parents_token_is_reported() {
    let parent = parent_with(exchange()).await;
    let proxy = proxy_with(
        &parent,
        TwoRounds {
            fails_with: Some("the logon session is gone"),
            ..TwoRounds::default()
        },
    )
    .await;
    let response = ask(&proxy, get("origin.example.com", "/", ""), false).await;
    assert_eq!(response.status, 502);
    let text = response.body_text();
    assert!(
        text.contains("the logon session is gone") && text.contains("HTTP@127.0.0.1"),
        "{text}"
    );
}

#[tokio::test]
async fn a_refused_second_token_is_not_tried_again_for_a_while() {
    // The second round is NTLM, made from the password of the logged-on user,
    // and a parent that refuses it has counted a failed logon.
    let parent = parent_with(Options {
        negotiate_exchange: Some(NegotiateExchange {
            first: FIRST.to_vec(),
            challenge: CHALLENGE.to_vec(),
            second: b"what the parent would accept".to_vec(),
        }),
        ..exchange()
    })
    .await;
    let proxy = proxy_with(&parent, TwoRounds::default()).await;

    let response = ask(&proxy, get("origin.example.com", "/", ""), false).await;
    assert_eq!(response.status, 502);
    let text = response.body_text();
    assert!(
        text.contains("did not accept the credentials of the logged-on user for HTTP@127.0.0.1"),
        "{text}"
    );
    // A bare probe, then the first token, then the rejected second: three in all.
    let tried = parent.requests().len();
    assert_eq!(tried, 3);

    let response = ask(&proxy, get("origin.example.com", "/", ""), false).await;
    assert_eq!(response.status, 503);
    assert_eq!(
        parent.requests().len(),
        tried,
        "nothing more goes to the parent"
    );
}
