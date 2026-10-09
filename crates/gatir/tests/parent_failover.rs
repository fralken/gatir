//! A parent proxy that accepts connections and ends them without a word (a
//! listener with nothing behind it, say) is given up on, and the next parent
//! of the list is tried, the way a browser does. An answer, whatever it says,
//! is not that: it is passed on as it is.

mod common;

use std::net::SocketAddr;

use common::*;
use gatir_testkit::http::RawClient;
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};
use gatir_testkit::tcp::{DeadServer, Hangup};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HANGUPS: [Hangup; 2] = [Hangup::Reset, Hangup::Close];

fn parents_toml(parents: &[SocketAddr]) -> String {
    let list: Vec<String> = parents.iter().map(|addr| format!("\"{addr}\"")).collect();
    format!("parents = [{}]\n", list.join(", "))
}

/// A parent that answers every request with `body` and opens a tunnel that
/// echoes for every CONNECT.
async fn live_parent(body: &'static str) -> MockOrigin {
    MockOrigin::start(move |request| {
        if request.method == "CONNECT" {
            Reply::raw("HTTP/1.1 200 Connection established\r\n\r\n").then_echo()
        } else {
            Reply::ok(body)
        }
    })
    .await
}

async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>) -> gatir_testkit::http::Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

/// The `[pac]` table of a script that returns `answer` for everything.
fn pac_returning(answer: &str) -> (TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy.pac");
    std::fs::write(
        &file,
        format!("function FindProxyForURL(url, host) {{ return \"{answer}\"; }}"),
    )
    .unwrap();
    let table = format!("[pac]\nfile = {:?}\n", file.display().to_string());
    (dir, table)
}

#[tokio::test]
async fn a_request_goes_to_the_next_parent_when_the_first_ends_the_connection() {
    for hangup in HANGUPS {
        let dead = DeadServer::start(hangup).await;
        let live = live_parent("live").await;
        let proxy = start_proxy(&parents_toml(&[dead.addr(), live.addr()])).await;

        for _ in 0..3 {
            let response = ask(&proxy, get("origin.example.com", "/x", "")).await;
            assert_eq!(response.status, 200, "{hangup:?}");
            assert_eq!(response.body_text(), "live", "{hangup:?}");
        }
        assert_eq!(live.requests().len(), 3, "{hangup:?}");
        assert_eq!(live.requests()[0].target, "http://origin.example.com/x");
        // It is not asked again: the parent that answered is the one in use.
        assert_eq!(dead.accepted(), 1, "{hangup:?}");
    }
}

#[tokio::test]
async fn a_parent_that_ended_a_connection_is_left_for_last_for_a_while() {
    // A script gives the same list every time, so what keeps the dead parent
    // from being tried first on every request is the memory of the failure.
    for hangup in HANGUPS {
        let dead = DeadServer::start(hangup).await;
        let live = live_parent("live").await;
        let (_dir, table) = pac_returning(&format!("PROXY {}; PROXY {}", dead.addr(), live.addr()));
        let proxy = start_proxy(&table).await;

        for _ in 0..3 {
            assert_eq!(
                ask(&proxy, get("origin.example.com", "/", ""))
                    .await
                    .body_text(),
                "live",
                "{hangup:?}"
            );
        }
        for _ in 0..2 {
            let tunnel = open_tunnel(&proxy, "secure.example.com:443").await;
            drop(tunnel);
        }
        assert_eq!(dead.accepted(), 1, "{hangup:?}");
    }
}

#[tokio::test]
async fn connect_goes_to_the_next_parent_when_the_first_ends_the_connection() {
    for hangup in HANGUPS {
        let dead = DeadServer::start(hangup).await;
        let live = live_parent("live").await;
        let proxy = start_proxy(&parents_toml(&[dead.addr(), live.addr()])).await;

        let mut client = RawClient::connect(proxy.addr).await.unwrap();
        client
            .send(connect_request("secure.example.com:443"))
            .await
            .unwrap();
        assert_eq!(client.read_response(true).await.unwrap().status, 200);
        client.send("ping").await.unwrap();
        assert_eq!(client.read_exact(4).await.unwrap(), b"ping", "{hangup:?}");
        assert_eq!(dead.accepted(), 1, "{hangup:?}");
    }
}

#[tokio::test]
async fn a_socks5_client_is_served_by_the_next_parent_too() {
    for hangup in HANGUPS {
        let dead = DeadServer::start(hangup).await;
        let live = live_parent("live").await;
        let proxy = start_proxy(&format!(
            "{}[socks5]\nlisten = [\"127.0.0.1:0\"]\n",
            parents_toml(&[dead.addr(), live.addr()])
        ))
        .await;

        let mut stream = TcpStream::connect(proxy.socks5[0]).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut chosen = [0u8; 2];
        stream.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [5, 0]);

        let name = b"secure.example.com";
        let mut request = vec![5, 1, 0, 3, u8::try_from(name.len()).unwrap()];
        request.extend(name);
        request.extend(443u16.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut answer = [0u8; 10];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[1], 0, "{hangup:?}: {answer:?}");

        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    }
}

#[tokio::test]
async fn when_every_parent_ends_the_connection_the_client_is_told_about_each() {
    for hangup in HANGUPS {
        let first = DeadServer::start(hangup).await;
        let second = DeadServer::start(hangup).await;
        let proxy = start_proxy(&parents_toml(&[first.addr(), second.addr()])).await;

        let response = ask(&proxy, get("origin.example.com", "/", "")).await;
        assert_eq!(response.status, 502, "{hangup:?}");
        let text = response.body_text();
        assert!(text.contains("No parent proxy is reachable"), "{text}");
        assert!(text.contains(&first.addr().to_string()), "{text}");
        assert!(text.contains(&second.addr().to_string()), "{text}");
        assert!(
            text.contains("closed the connection without answering"),
            "{text}"
        );
        assert_eq!((first.accepted(), second.accepted()), (1, 1), "{hangup:?}");

        let mut client = RawClient::connect(proxy.addr).await.unwrap();
        client
            .send(connect_request("secure.example.com:443"))
            .await
            .unwrap();
        let response = client.read_response(false).await.unwrap();
        assert_eq!(response.status, 502, "{hangup:?}");
        assert!(
            response.body_text().contains("closed the connection"),
            "{}",
            response.body_text()
        );
    }
}

#[tokio::test]
async fn an_answer_is_not_a_reason_to_try_the_next_parent() {
    let refusing = MockOrigin::start(|_| {
        Reply::raw("HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied")
    })
    .await;
    let live = live_parent("live").await;
    let proxy = start_proxy(&parents_toml(&[refusing.addr(), live.addr()])).await;

    let response = ask(&proxy, get("origin.example.com", "/", "")).await;
    assert_eq!(response.status, 403);
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client
        .send(connect_request("secure.example.com:443"))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 403);

    assert!(live.requests().is_empty());
    assert_eq!(live.connection_count(), 0);
}

#[tokio::test]
async fn a_request_with_a_body_is_not_lost_nor_sent_twice() {
    for hangup in HANGUPS {
        let dead = DeadServer::start(hangup).await;
        let live = live_parent("live").await;
        let proxy = start_proxy(&parents_toml(&[dead.addr(), live.addr()])).await;
        let post = "POST http://origin.example.com/in HTTP/1.1\r\n\
                    Host: origin.example.com\r\nContent-Length: 5\r\n\r\nhello";

        // The body may already have been given up by the time the parent is
        // known to be dead, in which case this one request cannot be repeated.
        let first = ask(&proxy, post).await;
        assert!(
            matches!(first.status, 200 | 502),
            "{hangup:?}: {}",
            first.status
        );
        if first.status == 200 {
            assert_eq!(live.requests().len(), 1, "{hangup:?}");
            assert_eq!(live.requests()[0].body, b"hello");
        }

        // Either way the dead parent has been given up on.
        let second = ask(&proxy, post).await;
        assert_eq!(second.status, 200, "{hangup:?}");
        assert_eq!(dead.accepted(), 1, "{hangup:?}");
        assert!(live.requests().iter().all(|seen| seen.body == b"hello"));
    }
}

#[tokio::test]
async fn the_next_hop_may_be_the_destination_itself() {
    // A parent takes the full URL and a server the path alone: the request is
    // written again for the hop it ends up going through.
    for hangup in HANGUPS {
        let dead = DeadServer::start(hangup).await;
        let origin = MockOrigin::start(|_| Reply::ok("direct")).await;
        let (_dir, table) = pac_returning(&format!("PROXY {}; DIRECT", dead.addr()));
        let proxy = start_proxy(&table).await;

        let authority = origin.addr().to_string();
        let response = ask(&proxy, get(&authority, "/page?x=1", "")).await;
        assert_eq!(response.status, 200, "{hangup:?}");
        assert_eq!(response.body_text(), "direct");
        assert_eq!(origin.requests()[0].target, "/page?x=1", "{hangup:?}");
    }
}

#[tokio::test]
async fn a_parent_that_wants_credentials_is_failed_over_too() {
    for hangup in HANGUPS {
        let dead = DeadServer::start(hangup).await;
        let live = MockNtlmParent::start(
            Account::new("alice", "CORP", "s3cret"),
            Options::default(),
            |_| Reply::ok("authenticated"),
        )
        .await;
        let proxy = start_proxy(&format!(
            "{}[credentials]\nusername = \"alice\"\ndomain = \"CORP\"\npassword = \"s3cret\"\n\
             method = \"ntlmv2\"\n",
            parents_toml(&[dead.addr(), live.addr()])
        ))
        .await;

        for _ in 0..2 {
            let response = ask(&proxy, get("origin.example.com", "/", "")).await;
            assert_eq!(response.status, 200, "{hangup:?}: {}", response.body_text());
            assert_eq!(response.body_text(), "authenticated");
        }
        assert_eq!(dead.accepted(), 1, "{hangup:?}");
    }
}
