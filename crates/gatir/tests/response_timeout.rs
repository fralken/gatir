//! How long gatir waits for a response from an origin server or a parent
//! proxy. The wait is timed from the moment the request has been sent, so a
//! slow upload is not cut off.

mod common;

use std::time::{Duration, Instant};

use common::*;
use gatir_testkit::http::RawClient;
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};

const LIMIT: &str = "[timeouts]\nresponse_secs = 1\n";

async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>) -> gatir_testkit::http::Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

#[tokio::test]
async fn a_slow_origin_gets_a_gateway_timeout() {
    let origin = MockOrigin::start(|_| Reply::ok("late").after(Duration::from_secs(4))).await;
    let proxy = start_proxy(LIMIT).await;

    let started = Instant::now();
    let response = ask(&proxy, get(&origin.authority(), "/", "")).await;
    let waited = started.elapsed();

    assert_eq!(response.status, 504);
    assert!(
        response
            .body_text()
            .contains("Timed out waiting for a response from the upstream server"),
        "{}",
        response.body_text()
    );
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(waited < Duration::from_secs(3), "{waited:?}");
}

#[tokio::test]
async fn a_response_within_the_limit_is_not_affected() {
    let origin =
        MockOrigin::start(|_| Reply::ok("in time").after(Duration::from_millis(300))).await;
    let proxy = start_proxy(LIMIT).await;

    let response = ask(&proxy, get(&origin.authority(), "/", "")).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body_text(), "in time");
}

#[tokio::test]
async fn a_slow_upload_is_not_a_slow_response() {
    let origin =
        MockOrigin::start(|request| Reply::ok(&format!("got {}", request.body.len()))).await;
    let proxy = start_proxy(LIMIT).await;
    let authority = origin.authority();

    // The whole upload takes longer than the limit, but the origin answers as
    // soon as it has all of it.
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(format!(
            "POST http://{authority}/up HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 10\r\n\r\nfirst"
        ))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1600)).await;
    client.send("later").await.unwrap();

    let response = client.read_response(false).await.unwrap();
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(response.body_text(), "got 10");
}

#[tokio::test]
async fn the_wait_starts_when_the_upload_is_over() {
    let origin = MockOrigin::start(|_| Reply::ok("late").after(Duration::from_secs(4))).await;
    let proxy = start_proxy(LIMIT).await;
    let authority = origin.authority();

    let started = Instant::now();
    let response = ask(
        &proxy,
        format!(
            "POST http://{authority}/up HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 4\r\n\r\ndata"
        ),
    )
    .await;
    let waited = started.elapsed();

    assert_eq!(response.status, 504);
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(waited < Duration::from_secs(3), "{waited:?}");
}

#[tokio::test]
async fn a_parent_that_never_answers_the_ntlm_negotiation_gives_a_gateway_timeout() {
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options {
            stall_on_negotiate: true,
            ..Options::default()
        },
        |_| Reply::ok("served"),
    )
    .await;
    let proxy = start_proxy(&format!(
        "{}{LIMIT}",
        ntlm_parent_config(parent.addr(), "ntlmv2", "s3cret")
    ))
    .await;

    // Each request waits for the limit, and none is left waiting behind another.
    let started = Instant::now();
    for _ in 0..2 {
        let response = ask(&proxy, get("origin.example.com", "/", "")).await;
        assert_eq!(response.status, 504);
        assert!(
            response
                .body_text()
                .contains("Timed out waiting for a response from the parent proxy"),
            "{}",
            response.body_text()
        );
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_parent_that_never_answers_a_connect_gives_a_gateway_timeout() {
    let parent = MockOrigin::start(|_| {
        Reply::raw("HTTP/1.1 200 Connection Established\r\n\r\n").after(Duration::from_secs(4))
    })
    .await;
    let proxy = start_proxy(&format!("parents = [\"{}\"]\n{LIMIT}", parent.addr())).await;

    let started = Instant::now();
    let response = ask(&proxy, connect_request("example.com:443")).await;

    assert_eq!(response.status, 504);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}
