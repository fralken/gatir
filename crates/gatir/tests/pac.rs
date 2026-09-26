//! A PAC file that chooses, for each request, where it goes. The parents are
//! mock servers, so a test sees which of them a request reached, and what it
//! looked like when it got there.

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use common::*;
use gatir::config::{Config, Overrides};
use gatir::proxy::Server;
use gatir_testkit::closed_port;
use gatir_testkit::http::RawClient;
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};
use tempfile::TempDir;

/// A server that names itself in every answer, and opens a tunnel for CONNECT.
async fn named(name: &'static str) -> MockOrigin {
    MockOrigin::start(move |request| {
        if request.method == "CONNECT" {
            Reply::raw("HTTP/1.1 200 Connection Established\r\n\r\n").then_echo()
        } else {
            Reply::ok(name)
        }
    })
    .await
}

/// Writes `script` to a file and returns the `[pac]` table that names it,
/// with `extra` lines inside it. The directory lives as long as the returned guard.
fn pac_table(script: &str, extra: &str) -> (TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy.pac");
    std::fs::write(&file, script).unwrap();
    let table = format!("[pac]\nfile = {:?}\n{extra}", file.display().to_string());
    (dir, table)
}

fn to(addr: SocketAddr) -> String {
    format!("PROXY {addr}")
}

async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>) -> gatir_testkit::http::Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

#[tokio::test]
async fn the_script_picks_the_parent_for_each_host() {
    let (a, b, origin) = (named("A").await, named("B").await, named("direct").await);
    let script = format!(
        r#"function FindProxyForURL(url, host) {{
             if (dnsDomainIs(host, ".a.test")) return "{}";
             if (dnsDomainIs(host, ".b.test")) return "{}";
             return "DIRECT";
           }}"#,
        to(a.addr()),
        to(b.addr())
    );
    let (_dir, table) = pac_table(&script, "");
    let proxy = start_proxy(&table).await;

    assert_eq!(
        ask(&proxy, get("x.a.test", "/one", "")).await.body_text(),
        "A"
    );
    assert_eq!(
        ask(&proxy, get("y.b.test", "/two", "")).await.body_text(),
        "B"
    );
    assert_eq!(
        ask(&proxy, get(&origin.authority(), "/three", ""))
            .await
            .body_text(),
        "direct"
    );

    // A parent is addressed with the whole URL, the destination itself is not.
    assert_eq!(a.requests()[0].target, "http://x.a.test/one");
    assert_eq!(b.requests()[0].target, "http://y.b.test/two");
    assert_eq!(origin.requests()[0].target, "/three");
}

#[tokio::test]
async fn the_script_sees_the_whole_url_with_the_host_in_lower_case() {
    let (a, origin) = (named("A").await, named("direct").await);
    let script = format!(
        r#"function FindProxyForURL(url, host) {{
             if (shExpMatch(url, "*/private/*")) return "{}";
             if (url === "http://mixed.test/Path?q=1" && host === "mixed.test") return "{}";
             return "DIRECT";
           }}"#,
        to(a.addr()),
        to(a.addr())
    );
    let (_dir, table) = pac_table(&script, "");
    let proxy = start_proxy(&table).await;

    // The same host, told apart by the path.
    let authority = origin.authority();
    assert_eq!(
        ask(&proxy, get(&authority, "/private/x", ""))
            .await
            .body_text(),
        "A"
    );
    assert_eq!(
        ask(&proxy, get(&authority, "/public/x", ""))
            .await
            .body_text(),
        "direct"
    );
    // The name is folded to lower case; the path is left alone.
    assert_eq!(
        ask(&proxy, get("Mixed.TEST", "/Path?q=1", ""))
            .await
            .body_text(),
        "A"
    );
}

#[tokio::test]
async fn a_list_moves_on_from_a_parent_that_is_down() {
    let (b, origin) = (named("B").await, named("direct").await);
    let dead = closed_port().await;
    // Down, then up: the second is used.
    let script = format!(
        r#"function FindProxyForURL(url, host) {{
             if (host === "list.test") return "{}; {}";
             // Direct first, and the destination is not there: the parent is.
             return "DIRECT; {}";
           }}"#,
        to(dead),
        to(b.addr()),
        to(b.addr())
    );
    let (_dir, table) = pac_table(&script, "");
    let proxy = start_proxy(&table).await;

    assert_eq!(
        ask(&proxy, get("list.test", "/", "")).await.body_text(),
        "B"
    );
    let closed = closed_port().await;
    assert_eq!(
        ask(&proxy, get(&closed.to_string(), "/", ""))
            .await
            .body_text(),
        "B"
    );

    // Direct is not the last resort of a script that does not say so, and when
    // it is reachable it is what gets used.
    assert_eq!(
        ask(&proxy, get(&origin.authority(), "/", ""))
            .await
            .body_text(),
        "direct"
    );
}

#[tokio::test]
async fn a_list_ending_in_direct_falls_back_to_the_destination() {
    let origin = named("direct").await;
    let dead = closed_port().await;
    let script = format!(
        r#"function FindProxyForURL(url, host) {{ return "{}; DIRECT"; }}"#,
        to(dead)
    );
    let (_dir, table) = pac_table(&script, "");
    let proxy = start_proxy(&table).await;

    let response = ask(&proxy, get(&origin.authority(), "/path", "")).await;
    assert_eq!(response.body_text(), "direct");
    // It went to the server itself, so the request is in origin form.
    assert_eq!(origin.requests()[0].target, "/path");
}

#[tokio::test]
async fn kinds_gatir_cannot_use_are_skipped() {
    let b = named("B").await;
    let script = format!(
        r#"function FindProxyForURL(url, host) {{
             if (host === "only.socks") return "SOCKS5 127.0.0.1:1; HTTPS 127.0.0.1:2";
             return "SOCKS5 127.0.0.1:1; {}";
           }}"#,
        to(b.addr())
    );
    let (_dir, table) = pac_table(&script, "");
    let proxy = start_proxy(&table).await;

    assert_eq!(ask(&proxy, get("any.test", "/", "")).await.body_text(), "B");

    let response = ask(&proxy, get("only.socks", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response
            .body_text()
            .contains("does not support: SOCKS5 127.0.0.1:1; HTTPS 127.0.0.1:2"),
        "{}",
        response.body_text()
    );
}

#[tokio::test]
async fn a_script_error_is_a_gateway_error_that_says_why() {
    let script = r#"function FindProxyForURL(url, host) {
                      if (host === "boom.test") throw new Error("the script gave up");
                      if (host === "number.test") return 42;
                      if (host === "empty.test") return "";
                      return "DIRECT";
                    }"#;
    let (_dir, table) = pac_table(script, "");
    let proxy = start_proxy(&table).await;
    let origin = named("direct").await;

    for (host, expected) in [
        ("boom.test", "the script gave up"),
        ("number.test", "must return a string"),
        ("empty.test", "no proxy gatir can read"),
    ] {
        let response = ask(&proxy, get(host, "/", "")).await;
        assert_eq!(response.status, 502, "{host}");
        let text = response.body_text();
        assert!(
            text.contains("The PAC script could not tell where to send this request"),
            "{text}"
        );
        assert!(text.contains(expected), "{host}: {text}");
    }
    // The proxy is fine, and so are the requests the script can answer.
    assert_eq!(
        ask(&proxy, get(&origin.authority(), "/", ""))
            .await
            .body_text(),
        "direct"
    );
}

#[tokio::test]
async fn a_script_that_never_ends_is_stopped_and_the_next_request_is_served() {
    let origin = named("direct").await;
    let script = r#"function FindProxyForURL(url, host) {
                      if (host === "loop.test") { while (true) {} }
                      return "DIRECT";
                    }"#;
    let (_dir, table) = pac_table(script, "time_limit_ms = 200\n");
    let proxy = start_proxy(&table).await;

    let started = Instant::now();
    let response = ask(&proxy, get("loop.test", "/", "")).await;
    assert_eq!(response.status, 502);
    assert!(
        response.body_text().contains("took longer than"),
        "{}",
        response.body_text()
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );

    assert_eq!(
        ask(&proxy, get(&origin.authority(), "/", ""))
            .await
            .body_text(),
        "direct"
    );
}

#[tokio::test]
async fn a_tunnel_is_decided_by_the_address_it_leads_to() {
    let (a, b) = (named("A").await, named("B").await);
    let script = format!(
        r#"function FindProxyForURL(url, host) {{
             if (url === "https://tunnel.test/") return "{}";
             if (url === "https://tunnel.test:8443/") return "{}";
             return "DIRECT";
           }}"#,
        to(a.addr()),
        to(b.addr())
    );
    let (_dir, table) = pac_table(&script, "");
    let proxy = start_proxy(&table).await;

    for authority in ["tunnel.test:443", "TUNNEL.test:8443"] {
        let mut client = open_tunnel(&proxy, authority).await;
        client.send("hello").await.unwrap();
        assert_eq!(client.read_exact(5).await.unwrap(), b"hello", "{authority}");
    }
    assert_eq!(a.requests()[0].method, "CONNECT");
    assert_eq!(a.requests()[0].target, "tunnel.test:443");
    assert_eq!(b.requests()[0].target, "TUNNEL.test:8443");
}

#[tokio::test]
async fn no_proxy_is_asked_before_the_script() {
    let (a, origin) = (named("A").await, named("direct").await);
    let script = format!(
        r#"function FindProxyForURL(url, host) {{ return "{}"; }}"#,
        to(a.addr())
    );
    let (_dir, table) = pac_table(&script, "");
    let proxy = start_proxy(&format!("no_proxy = [\"127.0.0.1\"]\n{table}")).await;

    assert_eq!(
        ask(&proxy, get(&origin.authority(), "/", ""))
            .await
            .body_text(),
        "direct"
    );
    assert!(a.requests().is_empty());
    assert_eq!(
        ask(&proxy, get("elsewhere.test", "/", ""))
            .await
            .body_text(),
        "A"
    );
}

#[tokio::test]
async fn the_parent_the_script_chose_can_ask_for_ntlm() {
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options::default(),
        |_| Reply::ok("served"),
    )
    .await;
    let script = format!(
        r#"function FindProxyForURL(url, host) {{ return "{}"; }}"#,
        to(parent.addr())
    );
    let (_dir, table) = pac_table(&script, "");
    let proxy = start_proxy(&format!(
        "{table}[credentials]\nusername = \"alice\"\ndomain = \"CORP\"\npassword = \"s3cret\"\n"
    ))
    .await;

    let response = ask(&proxy, get("any.test", "/", "")).await;
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(parent.messages(3), 1);
}

#[tokio::test]
async fn a_script_shared_by_many_requests_answers_them_all() {
    let (a, origin) = (named("A").await, named("direct").await);
    let script = format!(
        r#"function FindProxyForURL(url, host) {{
             return dnsDomainIs(host, ".a.test") ? "{}" : "DIRECT";
           }}"#,
        to(a.addr())
    );
    let (_dir, table) = pac_table(&script, "workers = 3\n");
    let proxy = start_proxy(&table).await;

    let mut tasks = Vec::new();
    for index in 0..24 {
        let (addr, authority) = (proxy.addr, origin.authority());
        tasks.push(tokio::spawn(async move {
            let mut client = RawClient::connect(addr).await.unwrap();
            let (host, expected) = if index % 2 == 0 {
                (format!("h{index}.a.test"), "A")
            } else {
                (authority, "direct")
            };
            client.send(get(&host, "/", "")).await.unwrap();
            (
                client.read_response(false).await.unwrap().body_text(),
                expected,
            )
        }));
    }
    for task in tasks {
        let (got, expected) = task.await.unwrap();
        assert_eq!(got, expected);
    }
}

// ---- a PAC file that cannot be used stops gatir from starting ----

async fn bind(table: &str) -> std::io::Error {
    let toml = format!("listen = [\"127.0.0.1:0\"]\n{table}");
    let config = Config::from_toml_str(&toml, Overrides::default()).unwrap();
    match Server::bind(&config).await {
        Ok(_) => panic!("the server should not start"),
        Err(err) => err,
    }
}

#[tokio::test]
async fn a_pac_file_that_cannot_be_used_is_refused_at_start_up() {
    let (_dir, syntax) = pac_table(
        "function FindProxyForURL(url, host) { return \"DIRECT\" ",
        "",
    );
    let error = bind(&syntax).await.to_string();
    assert!(error.contains("PAC file has an error"), "{error}");

    let (_dir, missing_function) = pac_table("var x = 1;", "");
    let error = bind(&missing_function).await.to_string();
    assert!(
        error.contains("does not define a function FindProxyForURL"),
        "{error}"
    );

    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent.pac");
    let error = bind(&format!(
        "[pac]\nfile = {:?}\n",
        absent.display().to_string()
    ))
    .await;
    assert!(
        error.to_string().contains("cannot use the PAC file"),
        "{error}"
    );
    assert!(Path::new(&absent).parent().is_some());
}
