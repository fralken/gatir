//! Header fields configured under `[headers]`.

mod common;

use common::*;
use gatir_testkit::http::RawClient;
use gatir_testkit::origin::{MockOrigin, Reply};

const RULES: &str = "[headers]\nUser-Agent = \"corp/1.0\"\nX-Added = \"yes\"\n";

#[tokio::test]
async fn configured_fields_replace_and_add_on_direct_requests() {
    let origin = MockOrigin::start(|_| Reply::ok("ok")).await;
    let proxy = start_proxy(RULES).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get(
            &origin.authority(),
            "/",
            "User-Agent: client/2.0\r\nX-Added: no\r\nX-Keep: as-is\r\n",
        ))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);

    let seen = &origin.requests()[0];
    assert_eq!(seen.headers.get_all("user-agent"), ["corp/1.0"]);
    assert_eq!(seen.headers.get_all("x-added"), ["yes"]);
    assert_eq!(seen.headers.get("x-keep"), Some("as-is"));
}

#[tokio::test]
async fn configured_fields_are_sent_to_a_parent() {
    let parent = MockOrigin::start(|_| Reply::ok("ok")).await;
    let config = format!("parents = [\"{}\"]\n{RULES}", parent.addr());
    let proxy = start_proxy(&config).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(get("origin.example.com", "/", "User-Agent: client/2.0\r\n"))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);

    let seen = &parent.requests()[0];
    assert_eq!(seen.headers.get_all("user-agent"), ["corp/1.0"]);
    assert_eq!(seen.headers.get("x-added"), Some("yes"));
}

#[tokio::test]
async fn configured_fields_are_sent_with_the_connect_to_a_parent() {
    let parent = MockOrigin::start(|_| {
        gatir_testkit::origin::Reply::raw("HTTP/1.1 200 Connection established\r\n\r\n").then_echo()
    })
    .await;
    let config = format!("parents = [\"{}\"]\n{RULES}", parent.addr());
    let proxy = start_proxy(&config).await;

    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(
            "CONNECT secure.example.com:443 HTTP/1.1\r\nHost: secure.example.com:443\r\n\
             User-Agent: client/2.0\r\n\r\n",
        )
        .await
        .unwrap();
    assert_eq!(client.read_response(true).await.unwrap().status, 200);

    let seen = &parent.requests()[0];
    assert_eq!(seen.method, "CONNECT");
    assert_eq!(seen.headers.get_all("user-agent"), ["corp/1.0"]);
    assert_eq!(seen.headers.get("x-added"), Some("yes"));
}

#[tokio::test]
async fn a_direct_tunnel_is_unaffected_by_configured_fields() {
    // There is no HTTP request to modify inside a direct tunnel.
    let echo = echo_server().await;
    let proxy = start_proxy(RULES).await;

    let mut client = open_tunnel(&proxy, &echo.authority()).await;
    client.send("plain bytes").await.unwrap();
    assert_eq!(client.read_exact(11).await.unwrap(), b"plain bytes");
}
