//! Static tunnels: a local port whose connections go to a fixed destination,
//! straight or through a parent proxy, without any protocol of their own.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use gatir::config::{Config, Overrides};
use gatir::proxy::Server;
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn tunnel_to(target: &str) -> String {
    format!("[[tunnels]]\nlisten = \"127.0.0.1:0\"\ntarget = \"{target}\"\n")
}

/// A parent that opens a tunnel to whatever it is asked and echoes what it gets.
async fn tunnelling_parent() -> MockOrigin {
    MockOrigin::start(|request| {
        if request.method == "CONNECT" {
            Reply::raw("HTTP/1.1 200 Connection Established\r\n\r\n").then_echo()
        } else {
            Reply::ok("not a tunnel")
        }
    })
    .await
}

async fn connect(addr: SocketAddr) -> TcpStream {
    TcpStream::connect(addr)
        .await
        .expect("connect to the tunnel")
}

/// Sends `data` and reads as many bytes back, as an echo does.
async fn echoed(client: &mut TcpStream, data: &[u8]) -> Vec<u8> {
    client.write_all(data).await.unwrap();
    let mut back = vec![0u8; data.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut back))
        .await
        .expect("the echo came back in time")
        .expect("the echo");
    back
}

/// True if the connection is closed by the other side without a single byte.
async fn closed_silently(client: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test]
async fn a_port_leads_to_its_destination_and_bytes_go_both_ways() {
    let echo = echo_server().await;
    let proxy = start_proxy(&tunnel_to(&echo.authority())).await;

    let mut client = connect(proxy.tunnels[0]).await;
    assert_eq!(
        echoed(&mut client, b"hello through the port").await,
        b"hello through the port"
    );

    // A large transfer arrives whole and in order.
    let data = pattern(1024 * 1024);
    let (mut read, mut write) = client.into_split();
    let sender = tokio::spawn({
        let data = data.clone();
        async move {
            write.write_all(&data).await.unwrap();
            write
        }
    });
    let mut back = vec![0u8; data.len()];
    read.read_exact(&mut back).await.unwrap();
    assert_eq!(fnv(&back), fnv(&data));
    sender.await.unwrap();
}

#[tokio::test]
async fn a_tunnel_through_a_parent_asks_it_to_connect() {
    let parent = tunnelling_parent().await;
    let proxy = start_proxy(&format!(
        "parents = [\"{}\"]\n[headers]\nX-Corp = \"on every request\"\n{}",
        parent.addr(),
        tunnel_to("git.example.com:22")
    ))
    .await;

    let mut client = connect(proxy.tunnels[0]).await;
    assert_eq!(echoed(&mut client, b"ssh-2.0").await, b"ssh-2.0");

    let seen = parent.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "CONNECT");
    assert_eq!(seen[0].target, "git.example.com:22");
    assert_eq!(seen[0].headers.get("host"), Some("git.example.com:22"));
    // The rules that apply to every request apply here too.
    assert_eq!(seen[0].headers.get("x-corp"), Some("on every request"));
}

#[tokio::test]
async fn no_proxy_destinations_are_reached_directly() {
    let parent = tunnelling_parent().await;
    let echo = echo_server().await;
    let proxy = start_proxy(&format!(
        "parents = [\"{}\"]\nno_proxy = [\"127.0.0.1\"]\n{}",
        parent.addr(),
        tunnel_to(&echo.authority())
    ))
    .await;

    let mut client = connect(proxy.tunnels[0]).await;
    assert_eq!(echoed(&mut client, b"direct").await, b"direct");
    assert!(parent.requests().is_empty());
}

#[tokio::test]
async fn a_pac_script_sees_the_address_a_tunnel_leads_to() {
    let parent = tunnelling_parent().await;
    let echo = echo_server().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy.pac");
    std::fs::write(
        &file,
        format!(
            r#"function FindProxyForURL(url, host) {{
                 if (url === "https://a.test:2222/" || url === "https://b.test/")
                   return "PROXY {}";
                 return "DIRECT";
               }}"#,
            parent.addr()
        ),
    )
    .unwrap();
    let proxy = start_proxy(&format!(
        "[pac]\nfile = {:?}\n{}{}{}",
        file.display().to_string(),
        tunnel_to("a.test:2222"),
        tunnel_to("b.test:443"),
        tunnel_to(&echo.authority())
    ))
    .await;

    for tunnel in &proxy.tunnels[..2] {
        let mut client = connect(*tunnel).await;
        assert_eq!(
            echoed(&mut client, b"via the parent").await,
            b"via the parent"
        );
    }
    let mut client = connect(proxy.tunnels[2]).await;
    assert_eq!(echoed(&mut client, b"direct").await, b"direct");

    let asked: Vec<String> = parent.requests().iter().map(|r| r.target.clone()).collect();
    assert_eq!(asked, ["a.test:2222", "b.test:443"]);
}

#[tokio::test]
async fn a_tunnel_through_an_ntlm_parent_authenticates() {
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options::default(),
        |request| {
            if request.method == "CONNECT" {
                Reply::raw("HTTP/1.1 200 Connection Established\r\n\r\n").then_echo()
            } else {
                Reply::ok("served")
            }
        },
    )
    .await;
    let proxy = start_proxy(&format!(
        "{}{}",
        ntlm_parent_config(parent.addr(), "ntlmv2", "s3cret"),
        tunnel_to("db.example.com:5432")
    ))
    .await;

    let mut client = connect(proxy.tunnels[0]).await;
    assert_eq!(echoed(&mut client, b"SELECT 1").await, b"SELECT 1");
    let seen = parent.requests();
    assert_eq!((seen[0].message, seen[0].served), (Some(1), false));
    assert_eq!((seen[1].message, seen[1].served), (Some(3), true));
    assert_eq!(seen[1].request.target, "db.example.com:5432");
}

#[tokio::test]
async fn a_client_is_disconnected_when_the_destination_cannot_be_reached() {
    // A parent that refuses, a parent that is not there, and a destination
    // nobody listens on.
    let refusing =
        MockOrigin::start(|_| Reply::raw("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
            .await;
    let closed = gatir_testkit::closed_port().await;

    for config in [
        format!(
            "parents = [\"{}\"]\n{}",
            refusing.addr(),
            tunnel_to("x.example.com:22")
        ),
        format!(
            "parents = [\"{closed}\"]\n{}",
            tunnel_to("x.example.com:22")
        ),
        tunnel_to(&closed.to_string()),
    ] {
        let proxy = start_proxy(&config).await;
        let mut client = connect(proxy.tunnels[0]).await;
        assert!(closed_silently(&mut client).await, "{config}");
        // The proxy is fine, and the next client is served the same way.
        let mut again = connect(proxy.tunnels[0]).await;
        assert!(closed_silently(&mut again).await, "{config}");
    }
    assert_eq!(refusing.requests().len(), 2);
}

#[tokio::test]
async fn clients_the_access_rules_reject_get_nothing() {
    let destination = MockOrigin::start(|_| Reply::ok("never asked")).await;
    let proxy = start_proxy(&format!(
        "[access]\ndefault = \"deny\"\n{}",
        tunnel_to(&destination.authority())
    ))
    .await;
    let mut client = connect(proxy.tunnels[0]).await;
    assert!(closed_silently(&mut client).await);
    assert_eq!(destination.connection_count(), 0);
}

#[tokio::test]
async fn a_silent_tunnel_is_closed_after_the_idle_timeout() {
    let echo = echo_server().await;
    let proxy = start_proxy(&format!(
        "[timeouts]\ntunnel_idle_secs = 1\n{}",
        tunnel_to(&echo.authority())
    ))
    .await;
    let mut client = connect(proxy.tunnels[0]).await;
    assert_eq!(echoed(&mut client, b"alive").await, b"alive");
    let started = std::time::Instant::now();
    assert!(closed_silently(&mut client).await);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn shutdown_waits_for_a_tunnel_and_a_forced_one_closes_it() {
    let echo = echo_server().await;
    let mut proxy = start_proxy(&tunnel_to(&echo.authority())).await;
    let mut client = connect(proxy.tunnels[0]).await;
    assert_eq!(echoed(&mut client, b"busy").await, b"busy");

    proxy.shutdown.cancel();
    assert!(
        !proxy.finished_within(Duration::from_millis(400)).await,
        "an active tunnel is waited for"
    );
    // It still carries bytes during the grace period.
    assert_eq!(echoed(&mut client, b"still here").await, b"still here");

    proxy.force.cancel();
    assert!(proxy.finished_within(Duration::from_secs(5)).await);
    assert!(closed_silently(&mut client).await);
}

#[tokio::test]
async fn a_port_that_is_taken_stops_gatir_from_starting() {
    let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = Config::from_toml_str(
        &format!(
            "listen = [\"127.0.0.1:0\"]\n[[tunnels]]\nlisten = \"{}\"\ntarget = \"x.example.com:22\"",
            taken.local_addr().unwrap()
        ),
        Overrides::default(),
    )
    .unwrap();
    let error = Server::bind(&config).await.err().expect("bind must fail");
    let text = error.to_string();
    assert!(
        text.contains("cannot listen on") && text.contains("tunnel"),
        "{text}"
    );
}
