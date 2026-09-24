//! Reuse of upstream connections.
//!
//! `MockOrigin::connection_count` tells how many TCP connections the upstream
//! server accepted, so a test can tell whether a connection was reused.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::*;
use gatir_testkit::http::RawClient;
use gatir_testkit::origin::{MockOrigin, Reply};

fn parents_toml(parent: &MockOrigin) -> String {
    format!("parents = [\"{}\"]\n", parent.addr())
}

/// Sends one GET on a fresh client connection and returns the response body.
async fn fetch(proxy: &TestProxy, authority: &str, path: &str) -> String {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(get(authority, path, "")).await.unwrap();
    client.read_response(false).await.unwrap().body_text()
}

#[tokio::test]
async fn sequential_requests_share_one_connection_to_the_origin() {
    let origin = MockOrigin::start(|request| Reply::ok(&request.target)).await;
    let proxy = start_proxy("").await;

    // Each request comes from a different client connection.
    for path in ["/a", "/b", "/c"] {
        assert_eq!(fetch(&proxy, &origin.authority(), path).await, path);
    }
    assert_eq!(origin.connection_count(), 1);
}

#[tokio::test]
async fn sequential_requests_share_one_connection_to_a_parent() {
    let parent = MockOrigin::start(|request| Reply::ok(&request.target)).await;
    let proxy = start_proxy(&parents_toml(&parent)).await;

    for path in ["/a", "/b", "/c"] {
        assert_eq!(
            fetch(&proxy, "origin.example.com", path).await,
            format!("http://origin.example.com{path}")
        );
    }
    assert_eq!(parent.connection_count(), 1);
}

#[tokio::test]
async fn chunked_and_head_responses_release_their_connection() {
    let origin = MockOrigin::start(|request| {
        if request.method == "HEAD" {
            Reply::raw("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
        } else {
            Reply::raw(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                 5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            )
        }
    })
    .await;
    let proxy = start_proxy("").await;
    let a = origin.authority();

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    for _ in 0..2 {
        client.send(get(&a, "/", "")).await.unwrap();
        assert_eq!(
            client.read_response(false).await.unwrap().body_text(),
            "hello world"
        );
        client
            .send(format!("HEAD http://{a}/ HTTP/1.1\r\nHost: {a}\r\n\r\n"))
            .await
            .unwrap();
        assert_eq!(client.read_response(true).await.unwrap().status, 200);
    }
    assert_eq!(origin.connection_count(), 1);
}

#[tokio::test]
async fn a_post_and_a_get_can_share_a_connection() {
    let origin = MockOrigin::start(|request| {
        Reply::ok(&format!("{}:{}", request.method, request.body.len()))
    })
    .await;
    let proxy = start_proxy("").await;
    let a = origin.authority();

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(format!(
            "POST http://{a}/up HTTP/1.1\r\nHost: {a}\r\nContent-Length: 4\r\n\r\ndata"
        ))
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "POST:4"
    );
    client.send(get(&a, "/", "")).await.unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "GET:0"
    );

    assert_eq!(origin.connection_count(), 1);
}

#[tokio::test]
async fn different_origins_do_not_share_connections() {
    let first = MockOrigin::start(|_| Reply::ok("first")).await;
    let second = MockOrigin::start(|_| Reply::ok("second")).await;
    let proxy = start_proxy("").await;

    for _ in 0..3 {
        assert_eq!(fetch(&proxy, &first.authority(), "/").await, "first");
        assert_eq!(fetch(&proxy, &second.authority(), "/").await, "second");
    }
    assert_eq!(first.connection_count(), 1);
    assert_eq!(second.connection_count(), 1);
}

#[tokio::test]
async fn a_connection_announced_as_closing_is_not_reused() {
    let origin = MockOrigin::start(|_| {
        Reply::raw("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
            .then_close()
    })
    .await;
    let proxy = start_proxy("").await;

    for _ in 0..3 {
        assert_eq!(fetch(&proxy, &origin.authority(), "/").await, "ok");
    }
    assert_eq!(origin.connection_count(), 3);
}

#[tokio::test]
async fn a_busy_connection_is_not_shared_with_a_concurrent_request() {
    let origin = MockOrigin::start(|_| Reply::ok("slow").after(Duration::from_millis(400))).await;
    let proxy = start_proxy("").await;

    let mut first = RawClient::connect(proxy.addr).await.unwrap();
    let mut second = RawClient::connect(proxy.addr).await.unwrap();
    first.send(get(&origin.authority(), "/", "")).await.unwrap();
    second
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();

    assert_eq!(
        first.read_response(false).await.unwrap().body_text(),
        "slow"
    );
    assert_eq!(
        second.read_response(false).await.unwrap().body_text(),
        "slow"
    );
    assert_eq!(origin.connection_count(), 2);
}

#[tokio::test]
async fn a_stale_pooled_connection_is_replaced_for_a_repeatable_request() {
    // The origin serves the first request, then hangs up on the second one
    // without answering, as a server does when it closes an idle connection at
    // the moment a request arrives.
    let calls = Arc::new(AtomicUsize::new(0));
    let origin = MockOrigin::start({
        let calls = calls.clone();
        move |_| match calls.fetch_add(1, Ordering::SeqCst) {
            1 => Reply::raw("").then_close(),
            call => Reply::ok(&format!("answer {call}")),
        }
    })
    .await;
    let proxy = start_proxy("").await;

    assert_eq!(fetch(&proxy, &origin.authority(), "/").await, "answer 0");
    // The client never notices the dead connection.
    assert_eq!(fetch(&proxy, &origin.authority(), "/").await, "answer 2");
    assert_eq!(origin.connection_count(), 2);
    assert_eq!(origin.requests().len(), 3);
}

#[tokio::test]
async fn a_request_with_a_body_is_not_repeated_on_a_stale_connection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let origin = MockOrigin::start({
        let calls = calls.clone();
        move |_| match calls.fetch_add(1, Ordering::SeqCst) {
            1 => Reply::raw("").then_close(),
            _ => Reply::ok("fine"),
        }
    })
    .await;
    let proxy = start_proxy("").await;
    let a = origin.authority();

    assert_eq!(fetch(&proxy, &a, "/").await, "fine");

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(format!(
            "POST http://{a}/pay HTTP/1.1\r\nHost: {a}\r\nContent-Length: 4\r\n\r\ndata"
        ))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 502);

    // Sent once, never silently repeated.
    let posts = origin
        .requests()
        .iter()
        .filter(|r| r.method == "POST")
        .count();
    assert_eq!(posts, 1);
}

#[tokio::test]
async fn concurrent_clients_never_receive_each_others_responses() {
    let origin = MockOrigin::start(|request| Reply::ok(&request.target)).await;
    let proxy = start_proxy("").await;
    let authority = origin.authority();
    let proxy_addr = proxy.addr;

    let mut tasks = Vec::new();
    for client_id in 0..20 {
        let authority = authority.clone();
        tasks.push(tokio::spawn(async move {
            let mut client = RawClient::connect(proxy_addr).await.unwrap();
            for request_id in 0..5 {
                let path = format!("/client{client_id}/request{request_id}");
                client.send(get(&authority, &path, "")).await.unwrap();
                let response = client.read_response(false).await.unwrap();
                assert_eq!(response.status, 200);
                assert_eq!(response.body_text(), path);
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    assert_eq!(origin.requests().len(), 100);
    // Connections were reused: far fewer than one per request. (The pool keeps
    // at most 8 idle connections per destination, so more than 20 can be opened
    // over time.)
    assert!(
        origin.connection_count() < 100,
        "{} connections for 100 requests",
        origin.connection_count()
    );
}
