//! A parent that offers NTLM and not Negotiate, with Negotiate configured: the
//! system's own NTLM, with the identity of the logged-on user (Windows does
//! that), takes over on the same connection. The system is a stand-in whose NTLM
//! is gatir's, with an account the mock parent knows or not, and the parent is
//! the mock, which checks the NTLM messages independently.

mod common;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use gatir::auth::ntlm;
use gatir::auth::{AuthError, SecurityContext, Step, TokenSource};
use gatir::config::{Config, Overrides};
use gatir_testkit::http::{RawClient, Response};
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, NegotiateExchange, Options};
use gatir_testkit::origin::Reply;
use hyper::header::HeaderValue;

/// The system: Negotiate tokens that no parent here accepts, and NTLM as the
/// logged-on user, whose password is `password`. `ntlm` says whether the system
/// can do NTLM by itself at all.
#[derive(Debug)]
struct System {
    password: &'static str,
    ntlm: bool,
}

impl System {
    fn of_alice() -> Self {
        Self {
            password: "s3cret",
            ntlm: true,
        }
    }
}

impl TokenSource for System {
    fn token(&self, service: &str) -> Result<Vec<u8>, AuthError> {
        Ok(format!("ticket for {service}").into_bytes())
    }

    /// Like SSPI, which does not call an exchange done after the first token.
    fn start(&self, service: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
        Ok(Box::new(Opening(service.to_owned())))
    }

    fn start_ntlm(&self, service: &str) -> Result<Option<Box<dyn SecurityContext>>, AuthError> {
        if !self.ntlm {
            return Ok(None);
        }
        let toml = format!(
            "[credentials]\nusername = \"alice\"\ndomain = \"CORP\"\npassword = \"{}\"\n\
             method = \"ntlmv2\"\n",
            self.password
        );
        let config = Config::from_toml_str(&toml, Overrides::default()).unwrap();
        Ok(Some(Box::new(NtlmContext {
            authenticator: ntlm::Authenticator::new(&config.credentials.unwrap()).unwrap(),
            service: service.to_owned(),
        })))
    }
}

/// The Negotiate context: a token that is the first and not the last, and a
/// second for a parent that answers with a token of its own.
#[derive(Debug)]
struct Opening(String);

impl SecurityContext for Opening {
    fn step(&mut self, from_parent: Option<&[u8]>) -> Result<Step, AuthError> {
        Ok(match from_parent {
            None => Step {
                token: Some(format!("ticket for {}", self.0).into_bytes()),
                complete: false,
            },
            Some(_) => Step {
                token: Some(format!("second for {}", self.0).into_bytes()),
                complete: true,
            },
        })
    }
}

/// NTLM as a security context: the messages, without the header around them.
#[derive(Debug)]
struct NtlmContext {
    authenticator: ntlm::Authenticator,
    service: String,
}

fn message(header: &HeaderValue) -> Vec<u8> {
    let (_, token) = header.to_str().unwrap().split_once(' ').unwrap();
    STANDARD.decode(token).unwrap()
}

impl SecurityContext for NtlmContext {
    fn step(&mut self, from_parent: Option<&[u8]>) -> Result<Step, AuthError> {
        match from_parent {
            None => Ok(Step {
                token: Some(message(&self.authenticator.first()?)),
                complete: false,
            }),
            Some(challenge) => {
                let field = ntlm::header(challenge);
                let answer = self
                    .authenticator
                    .respond(std::iter::once(&field))
                    .map_err(|err| AuthError::Exchange {
                        service: self.service.clone(),
                        reason: err.to_string(),
                    })?;
                Ok(Step {
                    token: Some(message(&answer)),
                    complete: true,
                })
            }
        }
    }
}

async fn parent_with(options: Options) -> MockNtlmParent {
    MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        options,
        |request| match request.method.as_str() {
            "CONNECT" => Reply::raw("HTTP/1.1 200 Connection Established\r\n\r\n").then_echo(),
            method => Reply::ok(&format!("{method} {} bytes", request.body.len())),
        },
    )
    .await
}

async fn proxy_with(parent: &MockNtlmParent, system: System) -> TestProxy {
    start_proxy_with_tokens(
        &format!(
            "parents = [\"{}\"]\n[credentials]\nmethod = \"negotiate\"\n",
            parent.addr()
        ),
        Arc::new(system),
    )
    .await
}

async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>) -> Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

#[tokio::test]
async fn ntlm_takes_over_when_the_parent_does_not_offer_negotiate() {
    let parent = parent_with(Options::default()).await;
    let proxy = proxy_with(&parent, System::of_alice()).await;

    let response = ask(&proxy, get("origin.example.com", "/page", "")).await;
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(response.body_text(), "GET 0 bytes");

    // A bare probe finds that only NTLM is offered, so no ticket is ever
    // asked for: the exchange runs entirely in NTLM on the same connection,
    // NEGOTIATE and then the real request with AUTHENTICATE.
    let seen = parent.requests();
    assert_eq!(seen.len(), 3);
    assert!(seen[0].negotiate.is_none() && seen[0].message.is_none());
    assert_eq!(seen[1].message, Some(1));
    assert_eq!(seen[2].message, Some(3));
    assert_eq!(
        seen.iter().map(|s| s.served).collect::<Vec<_>>(),
        [false, false, true]
    );
    assert!(seen.iter().all(|s| s.connection == seen[0].connection));
    assert!(
        seen.iter()
            .all(|s| s.request.target == "http://origin.example.com/page")
    );
}

#[tokio::test]
async fn a_post_is_sent_once_and_only_with_the_final_message() {
    let parent = parent_with(Options::default()).await;
    let proxy = proxy_with(&parent, System::of_alice()).await;

    let response = ask(
        &proxy,
        "POST http://origin.example.com/up HTTP/1.1\r\nHost: origin.example.com\r\n\
         Content-Length: 5\r\n\r\nhello",
    )
    .await;
    assert_eq!(response.body_text(), "POST 5 bytes");

    // Probes (a GET) carry the first two messages: nothing is done twice.
    let seen = parent.requests();
    let methods: Vec<&str> = seen.iter().map(|s| s.request.method.as_str()).collect();
    assert_eq!(methods, ["GET", "GET", "POST"]);
    assert!(seen[0].request.body.is_empty() && seen[1].request.body.is_empty());
    assert_eq!(seen[2].message, Some(3));
    assert_eq!(seen[2].request.body, b"hello");
}

#[tokio::test]
async fn a_tunnel_is_authenticated_the_same_way() {
    let parent = parent_with(Options::default()).await;
    let proxy = proxy_with(&parent, System::of_alice()).await;

    let mut client = open_tunnel(&proxy, "example.com:443").await;
    client.send("through the tunnel").await.unwrap();
    assert_eq!(client.read_exact(18).await.unwrap(), b"through the tunnel");

    let seen = parent.requests();
    assert!(seen.iter().all(|s| s.request.method == "CONNECT"));
    assert_eq!(
        seen.iter().map(|s| s.message).collect::<Vec<_>>(),
        [None, Some(1), Some(3)]
    );
}

#[tokio::test]
async fn the_connection_stays_authenticated_for_the_requests_after() {
    let parent = parent_with(Options::default()).await;
    let proxy = proxy_with(&parent, System::of_alice()).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    for path in ["/one", "/two"] {
        client
            .send(get("origin.example.com", path, ""))
            .await
            .unwrap();
        assert_eq!(client.read_response(false).await.unwrap().status, 200);
    }
    assert_eq!(parent.connection_count(), 1);
    assert_eq!(parent.requests().iter().filter(|s| s.served).count(), 2);
}

#[tokio::test]
async fn a_system_that_cannot_do_ntlm_by_itself_reports_what_the_parent_offers() {
    let parent = parent_with(Options::default()).await;
    let proxy = proxy_with(
        &parent,
        System {
            ntlm: false,
            ..System::of_alice()
        },
    )
    .await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("does not offer Negotiate authentication (it offers: NTLM)"),
        "{}",
        response.body_text()
    );
    // Nothing was tried in NTLM.
    assert_eq!(parent.messages(1), 0);
}

#[tokio::test]
async fn a_parent_that_offers_negotiate_too_gets_negotiate() {
    // It offers both, and takes the Negotiate token: the system's NTLM is not used.
    let parent = parent_with(Options {
        offers: vec!["Negotiate".to_owned(), "NTLM".to_owned()],
        negotiate_token: Some(b"ticket for HTTP@127.0.0.1".to_vec()),
        ..Options::default()
    })
    .await;
    let proxy = proxy_with(&parent, System::of_alice()).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(parent.messages(1), 0);
    // A bare probe, then the same request again with the ticket.
    assert_eq!(parent.requests().len(), 2);
}

#[tokio::test]
async fn a_parent_that_does_not_answer_ntlm_with_a_challenge_is_reported() {
    // It says NTLM, and ignores NTLM messages.
    let parent = parent_with(Options {
        ntlm: false,
        ..Options::default()
    })
    .await;
    let proxy = proxy_with(&parent, System::of_alice()).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("did not send an NTLM challenge"),
        "{}",
        response.body_text()
    );
}

#[tokio::test]
async fn a_refused_password_is_not_tried_again_for_a_while() {
    let parent = parent_with(Options::default()).await;
    // The password of the session is not the one the parent knows.
    let proxy = proxy_with(
        &parent,
        System {
            password: "stale",
            ntlm: true,
        },
    )
    .await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 502);
    let text = response.body_text();
    assert!(
        text.contains("did not accept the credentials of the logged-on user")
            && text.contains("sign out and in again"),
        "{text}"
    );
    let tried = parent.requests().len();
    assert_eq!(tried, 3);

    // The account has had its failed logon: nothing goes to the parent now.
    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 503);
    assert!(response.body_text().contains("Not trying again"));
    assert_eq!(parent.requests().len(), tried);
}

#[tokio::test]
async fn a_parent_that_answers_the_negotiate_token_with_its_own_is_not_sent_ntlm() {
    // It offers NTLM as well, but it is going on with Negotiate: the system
    // answers the token it sent, as it would with no NTLM of its own.
    let parent = parent_with(Options {
        offers: vec!["Negotiate".to_owned(), "NTLM".to_owned()],
        negotiate_exchange: Some(NegotiateExchange {
            first: b"ticket for HTTP@127.0.0.1".to_vec(),
            challenge: b"the parent's own token".to_vec(),
            second: b"second for HTTP@127.0.0.1".to_vec(),
        }),
        ..Options::default()
    })
    .await;
    let proxy = proxy_with(&parent, System::of_alice()).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(parent.messages(1), 0);
    // A bare probe, then the first ticket, then the second: three in all.
    assert_eq!(parent.requests().len(), 3);
}

#[tokio::test]
async fn a_parent_that_closes_the_connection_after_the_challenge_is_reported() {
    let parent = parent_with(Options {
        close_after_challenge: true,
        ..Options::default()
    })
    .await;
    let proxy = proxy_with(&parent, System::of_alice()).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("did not keep the connection open during authentication"),
        "{}",
        response.body_text()
    );
}

#[tokio::test]
async fn a_parent_that_closes_the_connection_when_it_refuses_the_negotiate_token_is_reported() {
    let parent = parent_with(Options {
        close_after_refusal: true,
        ..Options::default()
    })
    .await;
    let proxy = proxy_with(&parent, System::of_alice()).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("did not keep the connection open during authentication"),
        "{}",
        response.body_text()
    );
    assert_eq!(parent.messages(1), 0);
}
