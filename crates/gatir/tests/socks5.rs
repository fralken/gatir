//! The SOCKS5 server. The client here is written at the level of the bytes, on
//! purpose: it can send a message a piece at a time, or a wrong one, which a
//! library client would not.

mod common;

use std::time::{Duration, Instant};

use common::*;
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---- a SOCKS5 client, byte by byte ----

const NO_AUTH: u8 = 0;
const PASSWORD: u8 = 2;

fn ipv4(address: &str) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend(address.parse::<std::net::Ipv4Addr>().unwrap().octets());
    bytes
}

fn ipv6(address: &str) -> Vec<u8> {
    let mut bytes = vec![4];
    bytes.extend(address.parse::<std::net::Ipv6Addr>().unwrap().octets());
    bytes
}

fn domain(name: &str) -> Vec<u8> {
    let mut bytes = vec![3, u8::try_from(name.len()).unwrap()];
    bytes.extend(name.as_bytes());
    bytes
}

/// The request message: version, command, reserved, the address, the port.
fn request(command: u8, address: &[u8], port: u16) -> Vec<u8> {
    let mut bytes = vec![5, command, 0];
    bytes.extend(address);
    bytes.extend(port.to_be_bytes());
    bytes
}

fn connect_to(address: &[u8], port: u16) -> Vec<u8> {
    request(1, address, port)
}

#[derive(Debug, PartialEq, Eq)]
struct Answer {
    code: u8,
    /// The address type and the address, then the port.
    bound: Vec<u8>,
    port: u16,
}

async fn read_bytes(stream: &mut TcpStream, count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; count];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut bytes))
        .await
        .expect("an answer in time")
        .expect("an answer");
    bytes
}

async fn read_answer(stream: &mut TcpStream) -> Answer {
    let head = read_bytes(stream, 4).await;
    assert_eq!((head[0], head[2]), (5, 0), "{head:?}");
    let length = match head[3] {
        1 => 4,
        4 => 16,
        other => panic!("an answer with the address type {other}"),
    };
    let mut bound = vec![head[3]];
    bound.extend(read_bytes(stream, length).await);
    let port = read_bytes(stream, 2).await;
    Answer {
        code: head[1],
        bound,
        port: u16::from_be_bytes([port[0], port[1]]),
    }
}

async fn dial(proxy: &TestProxy) -> TcpStream {
    TcpStream::connect(proxy.socks5[0])
        .await
        .expect("connect to the SOCKS5 server")
}

/// Offers `methods` and returns the one the server chose.
async fn greet(stream: &mut TcpStream, methods: &[u8]) -> Vec<u8> {
    let mut hello = vec![5, u8::try_from(methods.len()).unwrap()];
    hello.extend(methods);
    stream.write_all(&hello).await.unwrap();
    read_bytes(stream, 2).await
}

/// The user name and password message of RFC 1929.
fn credentials(user: &[u8], password: &[u8]) -> Vec<u8> {
    let mut bytes = vec![1, u8::try_from(user.len()).unwrap()];
    bytes.extend(user);
    bytes.push(u8::try_from(password.len()).unwrap());
    bytes.extend(password);
    bytes
}

/// Connects, asks for `address:port` without a password, and returns the
/// answer with the stream.
async fn open(proxy: &TestProxy, address: &[u8], port: u16) -> (TcpStream, Answer) {
    let mut stream = dial(proxy).await;
    assert_eq!(greet(&mut stream, &[NO_AUTH]).await, [5, NO_AUTH]);
    stream.write_all(&connect_to(address, port)).await.unwrap();
    let answer = read_answer(&mut stream).await;
    (stream, answer)
}

async fn echoed(stream: &mut TcpStream, data: &[u8]) -> Vec<u8> {
    stream.write_all(data).await.unwrap();
    read_bytes(stream, data.len()).await
}

/// True if the other side closes the connection without another byte.
async fn closed_silently(stream: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

// ---- the configuration and the servers behind it ----

/// A configuration: top-level `keys`, the `[socks5]` table (with `table` lines
/// in it), and `other` tables after it.
fn socks5(keys: &str, table: &str, other: &str) -> String {
    format!("{keys}\n[socks5]\nlisten = [\"127.0.0.1:0\"]\n{table}\n{other}")
}

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

const NOT_SPECIFIED: [u8; 7] = [1, 0, 0, 0, 0, 0, 0];

// ---- the way it goes ----

#[tokio::test]
async fn a_destination_named_by_address_or_by_name_is_reached_directly() {
    let echo = echo_server().await;
    let port = echo.addr().port();
    let proxy = start_proxy(&socks5("", "", "")).await;

    for (what, address) in [("IPv4", ipv4("127.0.0.1")), ("name", domain("localhost"))] {
        let (mut stream, answer) = open(&proxy, &address, port).await;
        assert_eq!(answer.code, 0, "{what}");
        // For a direct connection the answer says where it starts.
        assert_eq!(answer.bound[0], 1, "{what}");
        assert_ne!(answer.port, 0, "{what}");
        assert_eq!(
            echoed(&mut stream, b"through SOCKS5").await,
            b"through SOCKS5"
        );
    }
}

#[tokio::test]
async fn an_ipv6_destination_is_reached_too() {
    let Ok(listener) = TcpListener::bind("[::1]:0").await else {
        eprintln!("no IPv6 loopback here: skipped");
        return;
    };
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let count = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..count]).await.unwrap();
    });
    let proxy = start_proxy(&socks5("", "", "")).await;

    let (mut stream, answer) = open(&proxy, &ipv6("::1"), port).await;
    assert_eq!(answer.code, 0);
    assert_eq!(answer.bound[0], 4);
    assert_eq!(echoed(&mut stream, b"six").await, b"six");
}

#[tokio::test]
async fn a_client_that_sends_one_byte_at_a_time_is_served() {
    let echo = echo_server().await;
    let proxy = start_proxy(&socks5("", "", "")).await;
    let mut stream = dial(&proxy).await;
    stream.set_nodelay(true).unwrap();

    let mut message = vec![5, 1, NO_AUTH];
    message.extend(connect_to(&domain("localhost"), echo.addr().port()));
    let (greeting, rest) = message.split_at(3);
    for part in [greeting, rest] {
        for byte in part {
            stream.write_all(&[*byte]).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        if part == greeting {
            assert_eq!(read_bytes(&mut stream, 2).await, [5, NO_AUTH]);
        }
    }
    assert_eq!(read_answer(&mut stream).await.code, 0);
    assert_eq!(echoed(&mut stream, b"slowly").await, b"slowly");
}

#[tokio::test]
async fn a_client_that_does_not_wait_for_the_answers_loses_no_byte() {
    let echo = echo_server().await;
    let proxy = start_proxy(&socks5("", "", "")).await;
    let mut stream = dial(&proxy).await;

    // The greeting, the request and the first bytes of data, in one write.
    let mut all = vec![5, 1, NO_AUTH];
    all.extend(connect_to(&ipv4("127.0.0.1"), echo.addr().port()));
    all.extend(b"first bytes");
    stream.write_all(&all).await.unwrap();

    assert_eq!(read_bytes(&mut stream, 2).await, [5, NO_AUTH]);
    assert_eq!(read_answer(&mut stream).await.code, 0);
    assert_eq!(read_bytes(&mut stream, 11).await, b"first bytes");
}

#[tokio::test]
async fn a_large_transfer_arrives_whole() {
    let echo = echo_server().await;
    let proxy = start_proxy(&socks5("", "", "")).await;
    let (stream, answer) = open(&proxy, &ipv4("127.0.0.1"), echo.addr().port()).await;
    assert_eq!(answer.code, 0);

    let data = pattern(1024 * 1024);
    let (mut read, mut write) = stream.into_split();
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

// ---- who may use it ----

#[tokio::test]
async fn a_user_name_and_password_are_asked_for_when_configured() {
    let echo = echo_server().await;
    let proxy = start_proxy(&socks5("", "username = \"bob\"\npassword = \"s3cret\"", "")).await;
    let port = echo.addr().port();

    // Right: the method is chosen even when the client also offers none.
    let mut stream = dial(&proxy).await;
    assert_eq!(
        greet(&mut stream, &[NO_AUTH, PASSWORD]).await,
        [5, PASSWORD]
    );
    stream
        .write_all(&credentials(b"bob", b"s3cret"))
        .await
        .unwrap();
    assert_eq!(read_bytes(&mut stream, 2).await, [1, 0]);
    stream
        .write_all(&connect_to(&ipv4("127.0.0.1"), port))
        .await
        .unwrap();
    assert_eq!(read_answer(&mut stream).await.code, 0);
    assert_eq!(echoed(&mut stream, b"welcome").await, b"welcome");

    // Wrong, in every way: it is told so, and disconnected before anything else.
    let wrong: [(&[u8], &[u8]); 7] = [
        (b"bob", b"s3cre"),
        (b"bob", b"s3cret!"),
        (b"bob", b"S3CRET"),
        (b"bo", b"s3cret"),
        (b"alice", b"s3cret"),
        (b"", b""),
        (b"bob", b""),
    ];
    for (user, password) in wrong {
        let mut stream = dial(&proxy).await;
        assert_eq!(greet(&mut stream, &[PASSWORD]).await, [5, PASSWORD]);
        stream
            .write_all(&credentials(user, password))
            .await
            .unwrap();
        assert_eq!(
            read_bytes(&mut stream, 2).await,
            [1, 1],
            "{user:?} {password:?}"
        );
        assert!(closed_silently(&mut stream).await);
    }
}

#[tokio::test]
async fn a_client_that_offers_no_acceptable_method_is_told_so() {
    let with_password =
        start_proxy(&socks5("", "username = \"bob\"\npassword = \"s3cret\"", "")).await;
    let open_server = start_proxy(&socks5("", "", "")).await;

    for (proxy, offered) in [
        (&with_password, vec![NO_AUTH]),
        (&with_password, vec![]),
        (&with_password, vec![0x01, 0x03, 0x80]),
        (&open_server, vec![PASSWORD]),
        (&open_server, vec![]),
    ] {
        let mut stream = dial(proxy).await;
        assert_eq!(greet(&mut stream, &offered).await, [5, 0xff], "{offered:?}");
        assert!(closed_silently(&mut stream).await);
    }
}

#[tokio::test]
async fn clients_the_access_rules_reject_get_nothing() {
    let destination = MockOrigin::start(|_| Reply::ok("never asked")).await;
    let proxy = start_proxy(&socks5("", "", "[access]\ndefault = \"deny\"\n")).await;
    let mut stream = dial(&proxy).await;
    let _ = stream.write_all(&[5, 1, NO_AUTH]).await;
    assert!(closed_silently(&mut stream).await);
    assert_eq!(destination.connection_count(), 0);
}

// ---- what is not SOCKS5, and what it cannot do ----

#[tokio::test]
async fn what_is_not_socks5_is_dropped_without_an_answer() {
    let proxy = start_proxy(&socks5("", "", "")).await;
    for bytes in [
        &[4u8, 1, 0, 80, 127, 0, 0, 1, 0][..],
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        &[0u8; 3],
    ] {
        let mut stream = dial(&proxy).await;
        stream.write_all(bytes).await.unwrap();
        assert!(closed_silently(&mut stream).await, "{bytes:?}");
    }

    // A request that is not SOCKS5 after a good greeting.
    let mut stream = dial(&proxy).await;
    assert_eq!(greet(&mut stream, &[NO_AUTH]).await, [5, NO_AUTH]);
    let mut bad = connect_to(&ipv4("127.0.0.1"), 80);
    bad[0] = 4;
    stream.write_all(&bad).await.unwrap();
    assert!(closed_silently(&mut stream).await);
}

#[tokio::test]
async fn only_connect_to_a_sensible_destination_is_supported() {
    let proxy = start_proxy(&socks5("", "", "")).await;
    let cases: [(&str, Vec<u8>, u8); 6] = [
        ("BIND", request(2, &ipv4("127.0.0.1"), 80), 7),
        ("UDP ASSOCIATE", request(3, &ipv4("0.0.0.0"), 0), 7),
        ("an unknown command", request(9, &ipv4("127.0.0.1"), 80), 7),
        (
            "an unknown type of address",
            request(1, &[9, 1, 2, 3], 80),
            8,
        ),
        ("an empty host name", request(1, &domain(""), 80), 4),
        ("port 0", connect_to(&ipv4("127.0.0.1"), 0), 2),
    ];
    for (what, message, code) in cases {
        let mut stream = dial(&proxy).await;
        assert_eq!(greet(&mut stream, &[NO_AUTH]).await, [5, NO_AUTH]);
        stream.write_all(&message).await.unwrap();
        let answer = read_answer(&mut stream).await;
        assert_eq!(answer.code, code, "{what}");
        assert_eq!(answer.bound, NOT_SPECIFIED[..5].to_vec(), "{what}");
        assert!(closed_silently(&mut stream).await, "{what}");
    }

    // Names no host has are refused before anything is done with them: not
    // looked up, and not put in a request to a parent.
    let parent = tunnelling_parent().await;
    let proxy = start_proxy(&socks5(
        &format!("parents = [\"{}\"]", parent.addr()),
        "",
        "",
    ))
    .await;
    for name in [
        "has space",
        "tab\t",
        "a/b",
        "user@host",
        "host:80",
        "a\r\nHost: evil",
        "caf\u{e9}",
        "x.example.com?a=b",
        "#fragment",
    ] {
        let mut stream = dial(&proxy).await;
        assert_eq!(greet(&mut stream, &[NO_AUTH]).await, [5, NO_AUTH]);
        stream
            .write_all(&connect_to(&domain(name), 80))
            .await
            .unwrap();
        assert_eq!(read_answer(&mut stream).await.code, 4, "{name:?}");
    }
    assert_eq!(parent.connection_count(), 0);
    assert!(parent.requests().is_empty());
}

#[tokio::test]
async fn a_client_that_takes_too_long_is_dropped() {
    let proxy = start_proxy(&socks5("", "", "[timeouts]\nclient_idle_secs = 1\n")).await;

    let mut silent = dial(&proxy).await;
    let started = Instant::now();
    assert!(closed_silently(&mut silent).await);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );

    // One that stops in the middle of its request gets the same.
    let mut halfway = dial(&proxy).await;
    assert_eq!(greet(&mut halfway, &[NO_AUTH]).await, [5, NO_AUTH]);
    halfway.write_all(&[5, 1, 0, 1, 127]).await.unwrap();
    assert!(closed_silently(&mut halfway).await);
}

// ---- where it goes ----

#[tokio::test]
async fn a_destination_behind_a_parent_is_asked_for_by_name_or_by_address() {
    let parent = tunnelling_parent().await;
    let proxy = start_proxy(&socks5(
        &format!("parents = [\"{}\"]", parent.addr()),
        "",
        "[headers]\nX-Corp = \"on every request\"\n",
    ))
    .await;

    for (address, port) in [
        (domain("git.example.com"), 22u16),
        (ipv4("10.9.8.7"), 5432),
        (ipv6("2001:db8::1"), 443),
    ] {
        let (mut stream, answer) = open(&proxy, &address, port).await;
        assert_eq!(answer.code, 0);
        // Through a parent there is no address to report.
        assert_eq!(
            (answer.bound, answer.port),
            (NOT_SPECIFIED[..5].to_vec(), 0)
        );
        assert_eq!(echoed(&mut stream, b"hello").await, b"hello");
    }

    let seen = parent.requests();
    let targets: Vec<&str> = seen.iter().map(|r| r.target.as_str()).collect();
    assert_eq!(
        targets,
        ["git.example.com:22", "10.9.8.7:5432", "[2001:db8::1]:443"]
    );
    for request in &seen {
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.headers.get("host"), Some(request.target.as_str()));
        assert_eq!(request.headers.get("x-corp"), Some("on every request"));
    }
}

#[tokio::test]
async fn no_proxy_destinations_are_reached_directly() {
    let parent = tunnelling_parent().await;
    let echo = echo_server().await;
    let proxy = start_proxy(&socks5(
        &format!(
            "parents = [\"{}\"]\nno_proxy = [\"127.0.0.1\", \"localhost\"]",
            parent.addr()
        ),
        "",
        "",
    ))
    .await;
    for address in [ipv4("127.0.0.1"), domain("localhost")] {
        let (mut stream, answer) = open(&proxy, &address, echo.addr().port()).await;
        assert_eq!(answer.code, 0);
        assert_eq!(echoed(&mut stream, b"direct").await, b"direct");
    }
    assert!(parent.requests().is_empty());
}

#[tokio::test]
async fn a_pac_script_sees_the_address_a_client_asks_for() {
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
    let proxy = start_proxy(&socks5(
        "",
        "",
        &format!("[pac]\nfile = {:?}\n", file.display().to_string()),
    ))
    .await;

    for (address, port) in [(domain("a.test"), 2222u16), (domain("B.TEST"), 443)] {
        let (mut stream, answer) = open(&proxy, &address, port).await;
        assert_eq!(answer.code, 0);
        assert_eq!(
            echoed(&mut stream, b"via the parent").await,
            b"via the parent"
        );
    }
    let (mut stream, answer) = open(&proxy, &ipv4("127.0.0.1"), echo.addr().port()).await;
    assert_eq!(answer.code, 0);
    assert_eq!(echoed(&mut stream, b"direct").await, b"direct");

    let asked: Vec<String> = parent.requests().iter().map(|r| r.target.clone()).collect();
    assert_eq!(asked, ["a.test:2222", "B.TEST:443"]);
}

#[tokio::test]
async fn a_parent_that_wants_ntlm_authenticates_the_tunnel() {
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
        "[socks5]\nlisten = [\"127.0.0.1:0\"]\n"
    ))
    .await;

    let (mut stream, answer) = open(&proxy, &domain("db.example.com"), 5432).await;
    assert_eq!(answer.code, 0);
    assert_eq!(echoed(&mut stream, b"SELECT 1").await, b"SELECT 1");
    let seen = parent.requests();
    assert_eq!((seen[0].message, seen[0].served), (Some(1), false));
    assert_eq!((seen[1].message, seen[1].served), (Some(3), true));
    assert_eq!(seen[1].request.target, "db.example.com:5432");
}

// ---- when it cannot go there ----

/// Asks for `address:port` and returns the code of the answer.
async fn refused_with(proxy: &TestProxy, address: &[u8], port: u16) -> u8 {
    let (mut stream, answer) = open(proxy, address, port).await;
    assert!(closed_silently(&mut stream).await);
    assert_eq!(answer.bound, NOT_SPECIFIED[..5].to_vec());
    answer.code
}

#[tokio::test]
async fn the_answer_says_why_a_destination_cannot_be_reached() {
    // Straight: nobody listens; the name does not exist.
    let closed = gatir_testkit::closed_port().await;
    let proxy = start_proxy(&socks5("", "", "[timeouts]\nconnect_secs = 10\n")).await;
    assert_eq!(
        refused_with(&proxy, &ipv4("127.0.0.1"), closed.port()).await,
        5
    );
    assert_eq!(
        refused_with(&proxy, &domain("nonexistent.invalid"), 80).await,
        4
    );

    // Through a parent that says no, or that is not there.
    for (status, code) in [
        (403u16, 2u8),
        (502, 4),
        (503, 4),
        (504, 6),
        (407, 1),
        (404, 1),
    ] {
        let parent = MockOrigin::start(move |_| {
            Reply::raw(format!("HTTP/1.1 {status} No\r\nContent-Length: 0\r\n\r\n"))
        })
        .await;
        let proxy = start_proxy(&socks5(
            &format!("parents = [\"{}\"]", parent.addr()),
            "",
            "",
        ))
        .await;
        assert_eq!(
            refused_with(&proxy, &domain("x.example.com"), 22).await,
            code,
            "{status}"
        );
    }
    let proxy = start_proxy(&socks5(&format!("parents = [\"{closed}\"]"), "", "")).await;
    assert_eq!(refused_with(&proxy, &domain("x.example.com"), 22).await, 3);
}

#[tokio::test]
async fn a_pac_script_that_fails_is_a_general_failure_not_a_direct_connection() {
    let echo = echo_server().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy.pac");
    std::fs::write(
        &file,
        "function FindProxyForURL(url, host) { throw new Error(\"broken\"); }",
    )
    .unwrap();
    let proxy = start_proxy(&socks5(
        "",
        "",
        &format!("[pac]\nfile = {:?}\n", file.display().to_string()),
    ))
    .await;
    assert_eq!(
        refused_with(&proxy, &ipv4("127.0.0.1"), echo.addr().port()).await,
        1
    );
}

#[tokio::test]
async fn rejected_credentials_are_a_general_failure() {
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options::default(),
        |_| Reply::ok("served"),
    )
    .await;
    let proxy = start_proxy(&format!(
        "{}{}",
        ntlm_parent_config(parent.addr(), "ntlmv2", "wrong"),
        "[socks5]\nlisten = [\"127.0.0.1:0\"]\n"
    ))
    .await;
    assert_eq!(refused_with(&proxy, &domain("x.example.com"), 22).await, 1);
    // gatir stays away from the account for a while: the next client fares the same.
    assert_eq!(refused_with(&proxy, &domain("x.example.com"), 22).await, 1);
    assert_eq!(parent.messages(3), 1);
}

// ---- shutting down ----

#[tokio::test]
async fn a_silent_tunnel_is_closed_after_the_idle_timeout() {
    let echo = echo_server().await;
    let proxy = start_proxy(&socks5("", "", "[timeouts]\ntunnel_idle_secs = 1\n")).await;
    let (mut stream, answer) = open(&proxy, &ipv4("127.0.0.1"), echo.addr().port()).await;
    assert_eq!(answer.code, 0);
    assert_eq!(echoed(&mut stream, b"alive").await, b"alive");
    let started = Instant::now();
    assert!(closed_silently(&mut stream).await);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn shutdown_waits_for_a_tunnel_and_a_forced_one_closes_it() {
    let echo = echo_server().await;
    let mut proxy = start_proxy(&socks5("", "", "")).await;
    let (mut stream, answer) = open(&proxy, &ipv4("127.0.0.1"), echo.addr().port()).await;
    assert_eq!(answer.code, 0);
    assert_eq!(echoed(&mut stream, b"busy").await, b"busy");

    proxy.shutdown.cancel();
    assert!(
        !proxy.finished_within(Duration::from_millis(400)).await,
        "an active tunnel is waited for"
    );
    assert_eq!(echoed(&mut stream, b"still here").await, b"still here");

    proxy.force.cancel();
    assert!(proxy.finished_within(Duration::from_secs(5)).await);
    assert!(closed_silently(&mut stream).await);
}

#[tokio::test]
async fn an_address_that_is_taken_stops_gatir_from_starting() {
    use gatir::config::{Config, Overrides};
    use gatir::proxy::Server;

    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = Config::from_toml_str(
        &format!(
            "listen = [\"127.0.0.1:0\"]\n[socks5]\nlisten = [\"{}\"]",
            taken.local_addr().unwrap()
        ),
        Overrides::default(),
    )
    .unwrap();
    let text = Server::bind(&config)
        .await
        .err()
        .expect("bind must fail")
        .to_string();
    assert!(
        text.contains("cannot listen on") && text.contains("SOCKS5"),
        "{text}"
    );
}
