//! Forwarding through parent proxies. The parent is a scripted HTTP server, so
//! the tests see exactly what gatir sends to it.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use gatir_testkit::closed_port;
use gatir_testkit::http::RawClient;
use gatir_testkit::origin::{MockOrigin, Reply};

fn parents_toml(parents: &[SocketAddr]) -> String {
    let list: Vec<String> = parents.iter().map(|addr| format!("\"{addr}\"")).collect();
    format!("parents = [{}]\n", list.join(", "))
}

async fn parent_answering(body: &'static str) -> MockOrigin {
    MockOrigin::start(move |_| Reply::ok(body)).await
}

#[tokio::test]
async fn a_request_goes_to_the_parent_in_absolute_form() {
    let parent = parent_answering("via parent").await;
    let proxy = start_proxy(&parents_toml(&[parent.addr()])).await;

    // The destination does not exist: gatir must not try to reach it.
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("origin.example.com", "/path?x=1", ""))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body_text(), "via parent");
    let seen = &parent.requests()[0];
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.target, "http://origin.example.com/path?x=1");
    assert_eq!(seen.headers.get("host"), Some("origin.example.com"));
}

#[tokio::test]
async fn the_destination_port_is_kept() {
    let parent = parent_answering("ok").await;
    let proxy = start_proxy(&parents_toml(&[parent.addr()])).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("origin.example.com:8080", "/x", ""))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);

    let seen = &parent.requests()[0];
    assert_eq!(seen.target, "http://origin.example.com:8080/x");
    assert_eq!(seen.headers.get("host"), Some("origin.example.com:8080"));
}

#[tokio::test]
async fn proxy_credentials_user_info_and_hop_by_hop_fields_do_not_reach_the_parent() {
    let parent = parent_answering("ok").await;
    let proxy = start_proxy(&parents_toml(&[parent.addr()])).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(
            "GET http://alice:hunter2@origin.example.com/ HTTP/1.1\r\n\
             Host: origin.example.com\r\n\
             Proxy-Authorization: Basic c2VjcmV0\r\n\
             Proxy-Connection: keep-alive\r\n\
             Connection: X-Private\r\nX-Private: 1\r\n\
             X-Keep: yes\r\n\r\n",
        )
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);

    let seen = &parent.requests()[0];
    assert_eq!(seen.target, "http://origin.example.com/");
    for name in ["proxy-authorization", "proxy-connection", "x-private"] {
        assert!(!seen.headers.contains(name), "{name} reached the parent");
    }
    assert_eq!(seen.headers.get("x-keep"), Some("yes"));
    let everything = format!("{seen:?}");
    assert!(
        !everything.contains("hunter2"),
        "user info reached the parent"
    );
}

#[tokio::test]
async fn bodies_and_chunked_responses_pass_through_a_parent() {
    let parent = MockOrigin::start(|request| {
        if request.method == "POST" {
            Reply::ok(&format!("got {}", request.body.len()))
        } else {
            Reply::raw(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                 5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            )
        }
    })
    .await;
    let proxy = start_proxy(&parents_toml(&[parent.addr()])).await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send(
            "POST http://origin.example.com/up HTTP/1.1\r\nHost: origin.example.com\r\n\
             Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "got 5"
    );

    client
        .send(get("origin.example.com", "/down", ""))
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "hello world"
    );
}

#[tokio::test]
async fn no_proxy_destinations_bypass_the_parent() {
    let parent = parent_answering("parent").await;
    let origin = MockOrigin::start(|_| Reply::ok("direct")).await;
    let config = format!(
        "{}no_proxy = [\"127.0.0.1\"]\n",
        parents_toml(&[parent.addr()])
    );
    let proxy = start_proxy(&config).await;
    let mut client = RawClient::connect(proxy.addr).await.unwrap();

    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "direct"
    );
    assert!(parent.requests().is_empty());

    client
        .send(get("origin.example.com", "/", ""))
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "parent"
    );
    assert_eq!(parent.requests().len(), 1);
}

#[tokio::test]
async fn the_next_parent_is_used_when_the_first_is_down() {
    let dead = closed_port().await;
    let live = parent_answering("live").await;
    let proxy = start_proxy(&parents_toml(&[dead, live.addr()])).await;

    for _ in 0..3 {
        let mut client = RawClient::connect(proxy.addr).await.unwrap();
        client
            .send(get("origin.example.com", "/", ""))
            .await
            .unwrap();
        let response = client.read_response(false).await.unwrap();
        assert_eq!(response.body_text(), "live");
    }
    assert_eq!(live.requests().len(), 3);
}

#[tokio::test]
async fn a_healthy_parent_is_kept_and_the_next_takes_over_when_it_dies() {
    let first = parent_answering("first").await;
    let second = parent_answering("second").await;
    let proxy = start_proxy(&parents_toml(&[first.addr(), second.addr()])).await;

    let ask = |proxy_addr| async move {
        let mut client = RawClient::connect(proxy_addr).await.unwrap();
        client
            .send(get("origin.example.com", "/", ""))
            .await
            .unwrap();
        client.read_response(false).await.unwrap().body_text()
    };

    assert_eq!(ask(proxy.addr).await, "first");
    assert_eq!(ask(proxy.addr).await, "first");
    assert!(second.requests().is_empty());

    drop(first);
    assert_eq!(ask(proxy.addr).await, "second");
    assert_eq!(ask(proxy.addr).await, "second");
}

#[tokio::test]
async fn when_every_parent_is_down_the_client_gets_a_502_naming_them() {
    let first = closed_port().await;
    let second = closed_port().await;
    let proxy = start_proxy(&parents_toml(&[first, second])).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("origin.example.com", "/", ""))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    assert_eq!(response.status, 502);
    let text = response.body_text();
    assert!(text.contains("No parent proxy is reachable"), "{text}");
    assert!(text.contains(&first.to_string()), "{text}");
    assert!(text.contains(&second.to_string()), "{text}");
}

#[tokio::test]
async fn a_misbehaving_parent_gives_502_and_the_proxy_recovers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let parent = MockOrigin::start({
        let calls = calls.clone();
        move |_| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Reply::raw("this is not http\r\n\r\n").then_close()
            } else {
                Reply::ok("recovered")
            }
        }
    })
    .await;
    let proxy = start_proxy(&parents_toml(&[parent.addr()])).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("origin.example.com", "/", ""))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 502);

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("origin.example.com", "/", ""))
        .await
        .unwrap();
    assert_eq!(
        client.read_response(false).await.unwrap().body_text(),
        "recovered"
    );
}

#[tokio::test]
async fn header_names_keep_their_capitalization_in_both_directions() {
    let parent = MockOrigin::start(|_| {
        Reply::raw("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-ReplY-CaSe: 1\r\n\r\nok")
    })
    .await;
    let proxy = start_proxy(&parents_toml(&[parent.addr()])).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("origin.example.com", "/", "X-CuStOm-HeAdEr: v\r\n"))
        .await
        .unwrap();
    let response = client.read_response(false).await.unwrap();

    let seen = &parent.requests()[0];
    let names: Vec<&str> = seen.headers.iter().map(|(name, _)| name).collect();
    assert!(names.contains(&"X-CuStOm-HeAdEr"), "{names:?}");
    assert!(names.contains(&"Host"), "{names:?}");

    let names: Vec<&str> = response.headers.iter().map(|(name, _)| name).collect();
    assert!(names.contains(&"X-ReplY-CaSe"), "{names:?}");
}
