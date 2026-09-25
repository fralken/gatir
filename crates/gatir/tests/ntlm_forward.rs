//! Requests forwarded through a parent proxy that demands NTLM. The parent is
//! a mock whose side of the exchange was written independently of gatir's, so
//! a request only gets through if the exchange is right on the wire.

mod common;

use common::*;
use gatir_testkit::http::RawClient;
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};

async fn parent_with(options: Options) -> MockNtlmParent {
    MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        options,
        |request| {
            if request.method == "HEAD" {
                Reply::raw("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n")
            } else {
                Reply::ok(&format!("{} {} bytes", request.method, request.body.len()))
            }
        },
    )
    .await
}

fn config_for(parent: std::net::SocketAddr, method: &str, password: &str) -> String {
    ntlm_parent_config(parent, method, password)
}

fn config(parent: &MockNtlmParent, password: &str) -> String {
    ntlm_parent_config(parent.addr(), "ntlmv2", password)
}

/// Sends `request` on a new connection to the proxy and reads the answer.
async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>) -> gatir_testkit::http::Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

#[tokio::test]
async fn a_get_is_authenticated_on_its_connection_before_it_is_served() {
    for method in ["ntlmv2", "ntlm2sr", "nt"] {
        let parent = parent_with(Options::default()).await;
        let proxy = start_proxy(&config_for(parent.addr(), method, "s3cret")).await;

        let response = ask(
            &proxy,
            get("origin.example.com", "/page?x=1", "X-Keep: yes\r\n"),
        )
        .await;
        assert_eq!(response.status, 200, "{method}: {}", response.body_text());
        assert_eq!(response.body_text(), "GET 0 bytes", "{method}");

        // The request itself opens the exchange, and is sent again with the proof.
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
            assert_eq!(each.request.method, "GET", "{method}");
            assert_eq!(each.request.target, "http://origin.example.com/page?x=1");
            assert_eq!(each.request.headers.get("x-keep"), Some("yes"), "{method}");
        }
    }
}

#[tokio::test]
async fn ntlmv2_follows_the_server_clock() {
    // The mock refuses a blob that lacks the timestamp and AV pairs it sent.
    let parent = parent_with(Options {
        timestamp: Some(116_444_736_000_000_000),
        ..Options::default()
    })
    .await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 200, "{}", response.body_text());
}

#[tokio::test]
async fn authenticated_connections_are_reused() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    for path in ["/one", "/two", "/three"] {
        let response = ask(&proxy, get("origin.example.com", path, "")).await;
        assert_eq!(response.status, 200);
    }

    assert_eq!(parent.connection_count(), 1);
    assert_eq!(parent.messages(1), 1);
    assert_eq!(parent.messages(3), 1);
    assert_eq!(parent.served().len(), 3);
}

#[tokio::test]
async fn a_post_is_preceded_by_a_get_that_opens_the_exchange() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    let response = ask(
        &proxy,
        "POST http://origin.example.com/upload HTTP/1.1\r\nHost: origin.example.com\r\n\
         Content-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(response.body_text(), "POST 5 bytes");

    let seen = parent.requests();
    assert_eq!(seen.len(), 2);
    // A probe, never the client's method: nothing is done twice.
    let probe = &seen[0];
    assert_eq!(probe.request.method, "GET");
    assert_eq!(probe.request.target, "http://origin.example.com/upload");
    assert_eq!((probe.message, probe.served), (Some(1), false));
    assert!(probe.request.body.is_empty());
    for field in ["content-length", "content-type", "transfer-encoding"] {
        assert!(
            !probe.request.headers.contains(field),
            "{field} in the probe"
        );
    }
    // The request itself goes once, with the proof and its whole body.
    let post = &seen[1];
    assert_eq!(post.request.method, "POST");
    assert_eq!((post.message, post.served), (Some(3), true));
    assert_eq!(post.request.body, b"hello");
    assert_eq!(probe.connection, post.connection);
}

#[tokio::test]
async fn a_chunked_upload_is_authenticated_the_same_way() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    let response = ask(
        &proxy,
        "POST http://origin.example.com/up HTTP/1.1\r\nHost: origin.example.com\r\n\
         Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(response.body_text(), "POST 11 bytes");

    let seen = parent.requests();
    assert_eq!(seen[0].request.method, "GET");
    assert_eq!(seen[1].request.method, "POST");
    assert_eq!(seen[1].request.body, b"hello world");
}

#[tokio::test]
async fn a_head_is_opened_with_a_get_as_well() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send("HEAD http://origin.example.com/ HTTP/1.1\r\nHost: origin.example.com\r\n\r\n")
        .await
        .unwrap();
    let response = client.read_response(true).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.headers.get("content-length"), Some("6"));

    let seen = parent.requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        (seen[0].request.method.as_str(), seen[0].message),
        ("GET", Some(1))
    );
    assert_eq!(
        (seen[1].request.method.as_str(), seen[1].message),
        ("HEAD", Some(3))
    );
    assert!(seen[1].served);
}

#[tokio::test]
async fn a_parent_that_asks_for_nothing_answers_a_get_by_itself() {
    let parent = MockOrigin::start(|_| Reply::ok("open")).await;
    let proxy = start_proxy(&config_for(parent.addr(), "ntlmv2", "s3cret")).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.body_text(), "open");
    assert_eq!(
        parent.requests().len(),
        1,
        "the answer is not asked for twice"
    );
}

#[tokio::test]
async fn a_parent_that_asks_for_nothing_still_sees_a_get_first_for_a_post() {
    let parent = MockOrigin::start(|request| Reply::ok(&request.method)).await;
    let proxy = start_proxy(&config_for(parent.addr(), "ntlmv2", "s3cret")).await;

    let response = ask(
        &proxy,
        "POST http://origin.example.com/x HTTP/1.1\r\nHost: origin.example.com\r\n\
         Content-Length: 2\r\n\r\nhi",
    )
    .await;
    assert_eq!(response.body_text(), "POST");

    let methods: Vec<_> = parent.requests().iter().map(|r| r.method.clone()).collect();
    assert_eq!(
        methods,
        ["GET", "POST"],
        "the probe is a GET, and it is not repeated as a POST"
    );
}

#[tokio::test]
async fn rejected_credentials_are_reported_and_not_tried_again() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&config(&parent, "not-the-password")).await;

    let first = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(first.status, 502);
    assert!(
        first
            .body_text()
            .contains("rejected the credentials of alice"),
        "{}",
        first.body_text()
    );

    let attempts = parent.messages(1);
    let second = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(second.status, 503);
    let retry_after: u64 = second.headers.get("retry-after").unwrap().parse().unwrap();
    assert!((1..=300).contains(&retry_after), "{retry_after}");

    // Not a single message more: every attempt counts against the account.
    assert_eq!(parent.messages(1), attempts);
    assert_eq!(parent.messages(3), 1);
    assert_eq!(parent.connection_count(), 1);
    assert!(parent.served().is_empty());
}

#[tokio::test]
async fn parallel_requests_with_wrong_credentials_make_one_attempt() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&config(&parent, "not-the-password")).await;

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
async fn parallel_requests_with_good_credentials_all_get_through() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

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

    assert_eq!(parent.served().len(), 8);
    // Each connection is authenticated once, whichever way they were shared.
    assert_eq!(parent.messages(3), parent.connection_count());
}

#[tokio::test]
async fn a_parent_without_ntlm_is_reported_with_the_schemes_it_offers() {
    let parent = parent_with(Options {
        ntlm: false,
        offers: vec!["Basic realm=\"corp\"".to_owned(), "Negotiate".to_owned()],
        ..Options::default()
    })
    .await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("does not offer NTLM authentication (it offers: Basic, Negotiate)"),
        "{}",
        response.body_text()
    );
    // Not a refusal of the credentials: the next request tries again.
    assert_eq!(
        ask(&proxy, get("origin.example.com", "/", "")).await.status,
        502
    );
    assert_eq!(parent.messages(1), 2);
}

#[tokio::test]
async fn a_parent_that_hangs_up_during_the_exchange_gives_a_gateway_error() {
    let parent = parent_with(Options {
        close_on_negotiate: true,
        ..Options::default()
    })
    .await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    for _ in 0..2 {
        let response = ask(&proxy, get("origin.example.com", "/", "")).await;
        assert_eq!(response.status, 502);
    }
    assert_eq!(
        parent.messages(1),
        2,
        "a hang-up is not a rejection: it is tried again"
    );
}

#[tokio::test]
async fn a_challenge_that_closes_the_connection_cannot_be_answered() {
    let parent = parent_with(Options {
        close_after_challenge: true,
        ..Options::default()
    })
    .await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("did not keep the connection open"),
        "{}",
        response.body_text()
    );
}

#[tokio::test]
async fn a_pooled_connection_that_loses_its_authentication_is_replaced() {
    let parent = parent_with(Options {
        forget_after: Some(1),
        ..Options::default()
    })
    .await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    assert_eq!(
        ask(&proxy, get("origin.example.com", "/one", ""))
            .await
            .status,
        200
    );
    // The pooled connection is asked for proof again: gatir goes on a new one.
    let second = ask(&proxy, get("origin.example.com", "/two", "")).await;
    assert_eq!(second.status, 200, "{}", second.body_text());

    assert_eq!(parent.connection_count(), 2);
    assert_eq!(parent.messages(1), 2);
    assert_eq!(parent.served().len(), 2);
}

#[tokio::test]
async fn a_post_cannot_be_repeated_when_its_connection_loses_authentication() {
    let parent = parent_with(Options {
        forget_after: Some(1),
        ..Options::default()
    })
    .await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;
    assert_eq!(
        ask(&proxy, get("origin.example.com", "/one", ""))
            .await
            .status,
        200
    );

    let response = ask(
        &proxy,
        "POST http://origin.example.com/x HTTP/1.1\r\nHost: origin.example.com\r\n\
         Content-Length: 2\r\n\r\nhi",
    )
    .await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("asked for authentication again"),
        "{}",
        response.body_text()
    );
    // Only the first GET was ever served: the POST was never applied.
    assert_eq!(parent.served().len(), 1);

    // The next request works.
    assert_eq!(
        ask(&proxy, get("origin.example.com", "/three", ""))
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn the_clients_own_proxy_credentials_are_never_used() {
    let parent = parent_with(Options::default()).await;
    let proxy = start_proxy(&config(&parent, "s3cret")).await;

    let response = ask(
        &proxy,
        get(
            "origin.example.com",
            "/",
            "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n",
        ),
    )
    .await;
    assert_eq!(response.status, 200);
    for seen in parent.requests() {
        let value = seen.request.headers.get("proxy-authorization").unwrap();
        assert!(value.starts_with("NTLM "), "{value}");
    }
}

#[tokio::test]
async fn destinations_reached_directly_get_no_credentials() {
    let parent = parent_with(Options::default()).await;
    let origin = MockOrigin::start(|_| Reply::ok("direct")).await;
    let proxy = start_proxy(&format!(
        "parents = [\"{}\"]\nno_proxy = [\"127.0.0.1\"]\n\
         [credentials]\nusername = \"alice\"\ndomain = \"CORP\"\npassword = \"s3cret\"\n",
        parent.addr()
    ))
    .await;

    let response = ask(&proxy, get(&origin.authority(), "/", "")).await;
    assert_eq!(response.body_text(), "direct");
    assert!(!origin.requests()[0].headers.contains("proxy-authorization"));
    assert!(parent.requests().is_empty());
}
