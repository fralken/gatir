//! CONNECT tunnels through a parent proxy that demands NTLM. The parent is a
//! mock whose side of the exchange was written independently of gatir's.

mod common;

use common::*;
use gatir_testkit::http::RawClient;
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};

const DESTINATION: &str = "example.com:443";

fn tunnel_opened() -> Reply {
    Reply::raw("HTTP/1.1 200 Connection Established\r\n\r\n").then_echo()
}

async fn parent_with(options: Options) -> MockNtlmParent {
    MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        options,
        |request| {
            if request.method == "CONNECT" {
                tunnel_opened()
            } else {
                Reply::ok("served")
            }
        },
    )
    .await
}

async fn connect_status(proxy: &TestProxy) -> gatir_testkit::http::Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(connect_request(DESTINATION)).await.unwrap();
    client.read_response(false).await.unwrap()
}

#[tokio::test]
async fn a_tunnel_opens_once_the_parent_has_authenticated_the_connection() {
    for method in ["ntlmv2", "ntlm2sr", "nt"] {
        let parent = parent_with(Options::default()).await;
        let proxy = start_proxy(&ntlm_parent_config(parent.addr(), method, "s3cret")).await;

        let mut client = open_tunnel(&proxy, DESTINATION).await;
        client.send("through the tunnel").await.unwrap();
        assert_eq!(client.read_exact(18).await.unwrap(), b"through the tunnel");

        // The CONNECT itself opens the exchange, and is sent again with the proof.
        let seen = parent.requests();
        assert_eq!(seen.len(), 2, "{method}");
        assert_eq!(
            (seen[0].message, seen[0].served),
            (Some(1), false),
            "{method}"
        );
        assert_eq!(
            (seen[1].message, seen[1].served),
            (Some(3), true),
            "{method}"
        );
        assert_eq!(seen[0].connection, seen[1].connection, "{method}");
        for each in &seen {
            assert_eq!(each.request.method, "CONNECT");
            assert_eq!(each.request.target, DESTINATION);
            assert_eq!(each.request.headers.get("host"), Some(DESTINATION));
        }
    }
}

#[tokio::test]
async fn every_tunnel_authenticates_its_own_connection() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&ntlm_parent_config(parent.addr(), "ntlmv2", "s3cret")).await;

    let mut tunnels = Vec::new();
    for _ in 0..3 {
        tunnels.push(open_tunnel(&proxy, DESTINATION).await);
    }
    assert_eq!(parent.connection_count(), 3);
    assert_eq!(parent.messages(1), 3);
    assert_eq!(parent.messages(3), 3);
}

#[tokio::test]
async fn a_parent_that_asks_for_nothing_opens_the_tunnel_at_once() {
    let parent = MockOrigin::start(|_| tunnel_opened()).await;
    let proxy = start_proxy(&ntlm_parent_config(parent.addr(), "ntlmv2", "s3cret")).await;

    let mut client = open_tunnel(&proxy, DESTINATION).await;
    client.send("ping").await.unwrap();
    assert_eq!(client.read_exact(4).await.unwrap(), b"ping");
    assert_eq!(parent.requests().len(), 1, "the CONNECT is not sent twice");
}

#[tokio::test]
async fn rejected_credentials_give_a_gateway_error_and_stop_every_attempt() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&ntlm_parent_config(
        parent.addr(),
        "ntlmv2",
        "not-the-password",
    ))
    .await;

    let refused = connect_status(&proxy).await;
    assert_eq!(refused.status, 502);
    assert!(
        refused
            .body_text()
            .contains("rejected the credentials of alice"),
        "{}",
        refused.body_text()
    );

    // The pause covers the whole parent: a plain request is turned away too.
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("origin.example.com", "/", ""))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 503);
    assert_eq!(connect_status(&proxy).await.status, 503);

    assert_eq!(parent.messages(1), 1);
    assert_eq!(parent.messages(3), 1);
    assert_eq!(parent.connection_count(), 1);
}

#[tokio::test]
async fn a_refusal_by_policy_after_authentication_is_passed_on() {
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options::default(),
        |request| {
            if request.method == "CONNECT" {
                Reply::raw("HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\nDenied")
            } else {
                Reply::ok("served")
            }
        },
    )
    .await;
    let proxy = start_proxy(&ntlm_parent_config(parent.addr(), "ntlmv2", "s3cret")).await;

    let refused = connect_status(&proxy).await;
    assert_eq!(refused.status, 403);
    assert_eq!(refused.body_text(), "Denied");

    // The credentials were taken: nobody is kept waiting for them.
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("origin.example.com", "/", ""))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);
}

#[tokio::test]
async fn parallel_tunnels_with_wrong_credentials_make_one_attempt() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&ntlm_parent_config(
        parent.addr(),
        "ntlmv2",
        "not-the-password",
    ))
    .await;

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let addr = proxy.addr;
        tasks.push(tokio::spawn(async move {
            let mut client = RawClient::connect(addr).await.unwrap();
            client.send(connect_request(DESTINATION)).await.unwrap();
            client.read_response(false).await.unwrap().status
        }));
    }
    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.unwrap());
    }

    assert_eq!(
        statuses.iter().filter(|s| **s == 502).count(),
        1,
        "{statuses:?}"
    );
    assert_eq!(
        statuses.iter().filter(|s| **s == 503).count(),
        7,
        "{statuses:?}"
    );
    assert_eq!(
        parent.messages(3),
        1,
        "the account must not see a burst of failed logons"
    );
}

#[tokio::test]
async fn a_parent_without_ntlm_is_reported_with_the_schemes_it_offers() {
    let parent = parent_with(Options {
        ntlm: false,
        offers: vec!["Basic realm=\"corp\"".to_owned(), "Negotiate".to_owned()],
        ..Options::default()
    })
    .await;
    let proxy = start_proxy(&ntlm_parent_config(parent.addr(), "ntlmv2", "s3cret")).await;

    let response = connect_status(&proxy).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("does not offer NTLM authentication (it offers: Basic, Negotiate)"),
        "{}",
        response.body_text()
    );
}

#[tokio::test]
async fn a_challenge_that_closes_the_connection_cannot_be_answered() {
    let parent = parent_with(Options {
        close_after_challenge: true,
        ..Options::default()
    })
    .await;
    let proxy = start_proxy(&ntlm_parent_config(parent.addr(), "ntlmv2", "s3cret")).await;

    let response = connect_status(&proxy).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("did not keep the connection open"),
        "{}",
        response.body_text()
    );
}
