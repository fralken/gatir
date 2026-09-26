//! A running proxy takes the settings of a configuration read again: where
//! requests go, who may make them, and how they authenticate, without a
//! restart and without disturbing what is in flight.

mod common;

use std::time::{Duration, Instant};

use common::*;
use gatir::config::{Config, Overrides};
use gatir_testkit::http::RawClient;
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A server that names itself in every answer.
async fn named(name: &'static str) -> MockOrigin {
    MockOrigin::start(move |_| Reply::ok(name)).await
}

/// Applies `extra`, with the address the proxies of these tests listen on, and
/// returns what still needs a restart.
async fn apply(proxy: &TestProxy, extra: &str) -> Vec<&'static str> {
    let config = Config::from_toml_str(
        &format!("listen = [\"127.0.0.1:0\"]\n{extra}"),
        Overrides::default(),
    )
    .expect("test configuration");
    proxy.reloader.apply(&config).await.expect("the reload")
}

async fn ask(proxy: &TestProxy, request: impl AsRef<[u8]>) -> gatir_testkit::http::Response {
    let mut client = RawClient::connect(proxy.addr).await.unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

/// What the parent (or the origin) named in the answer, for a request to `site.test`.
async fn answer(proxy: &TestProxy) -> String {
    ask(proxy, get("site.test", "/", "")).await.body_text()
}

fn parents(parent: &MockOrigin) -> String {
    format!("parents = [\"{}\"]\n", parent.addr())
}

#[tokio::test]
async fn a_reload_changes_where_requests_go() {
    let (a, b) = (named("A").await, named("B").await);
    let proxy = start_proxy(&parents(&a)).await;
    assert_eq!(answer(&proxy).await, "A");

    assert_eq!(apply(&proxy, &parents(&b)).await, Vec::<&str>::new());
    assert_eq!(answer(&proxy).await, "B");
    // The connection kept for A is not used for anything any more.
    assert_eq!(a.requests().len(), 1);
    assert_eq!(b.requests().len(), 1);

    // And back.
    apply(&proxy, &parents(&a)).await;
    assert_eq!(answer(&proxy).await, "A");
}

#[tokio::test]
async fn a_reload_changes_who_may_connect() {
    let origin = named("served").await;
    let proxy = start_proxy("").await;
    assert_eq!(
        ask(&proxy, get(&origin.authority(), "/", "")).await.status,
        200
    );

    apply(&proxy, "[access]\ndefault = \"deny\"\n").await;
    assert_eq!(
        ask(&proxy, get(&origin.authority(), "/", "")).await.status,
        403
    );

    apply(&proxy, "").await;
    assert_eq!(
        ask(&proxy, get(&origin.authority(), "/", "")).await.status,
        200
    );
}

#[tokio::test]
async fn a_reload_changes_what_goes_direct() {
    let parent = named("parent").await;
    let origin = named("origin").await;
    let proxy = start_proxy(&parents(&parent)).await;
    let request = get(&origin.authority(), "/", "");
    assert_eq!(ask(&proxy, &request).await.body_text(), "parent");

    apply(
        &proxy,
        &format!("{}no_proxy = [\"127.0.0.1\"]\n", parents(&parent)),
    )
    .await;
    assert_eq!(ask(&proxy, &request).await.body_text(), "origin");
}

#[tokio::test]
async fn a_reload_changes_the_header_fields_sent_on() {
    let parent = named("parent").await;
    let proxy = start_proxy(&format!("{}[headers]\nX-Env = \"one\"\n", parents(&parent))).await;
    answer(&proxy).await;
    apply(
        &proxy,
        &format!("{}[headers]\nX-Env = \"two\"\n", parents(&parent)),
    )
    .await;
    answer(&proxy).await;

    let seen: Vec<_> = parent
        .requests()
        .iter()
        .map(|request| request.headers.get("x-env").map(str::to_owned))
        .collect();
    assert_eq!(seen, [Some("one".to_owned()), Some("two".to_owned())]);
}

#[tokio::test]
async fn a_request_in_flight_finishes_under_the_settings_it_began_with() {
    let slow = MockOrigin::start(|_| Reply::ok("A").after(Duration::from_millis(700))).await;
    let fast = named("B").await;
    let proxy = start_proxy(&parents(&slow)).await;

    let in_flight = tokio::spawn({
        let addr = proxy.addr;
        async move {
            let mut client = RawClient::connect(addr).await.unwrap();
            client.send(get("site.test", "/", "")).await.unwrap();
            client.read_response(false).await.unwrap().body_text()
        }
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    apply(&proxy, &parents(&fast)).await;

    // A new request already goes to B; the one that was sent still gets A.
    assert_eq!(answer(&proxy).await, "B");
    assert_eq!(in_flight.await.unwrap(), "A");
}

// ---- credentials ----

fn ntlm_config(parent: &MockNtlmParent, password: &str) -> String {
    ntlm_parent_config(parent.addr(), "ntlmv2", password)
}

async fn account_parent() -> MockNtlmParent {
    MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options::default(),
        |_| Reply::ok("served"),
    )
    .await
}

#[tokio::test]
async fn new_credentials_are_used_at_once_and_old_connections_are_not() {
    let parent = account_parent().await;
    let proxy = start_proxy(&ntlm_config(&parent, "s3cret")).await;
    assert_eq!(answer(&proxy).await, "served");
    assert_eq!(parent.messages(3), 1);

    // Another password: the connection that had been authenticated with the
    // first must not carry the next request, or it would be answered as alice.
    apply(&proxy, &ntlm_config(&parent, "not-it")).await;
    let response = ask(&proxy, get("site.test", "/", "")).await;
    assert_eq!(response.status, 502, "{}", response.body_text());
    assert_eq!(parent.messages(3), 2);
    assert_eq!(parent.connection_count(), 2);

    // And the right one again, at once: the account was refused, but with
    // other credentials.
    apply(&proxy, &ntlm_config(&parent, "s3cret")).await;
    assert_eq!(answer(&proxy).await, "served");
}

#[tokio::test]
async fn a_connection_in_use_during_a_reload_is_not_kept_afterwards() {
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options::default(),
        |_| Reply::ok("served").after(Duration::from_millis(600)),
    )
    .await;
    let proxy = start_proxy(&ntlm_config(&parent, "s3cret")).await;

    // The request has its connection, authenticated as alice, and waits.
    let in_flight = tokio::spawn({
        let addr = proxy.addr;
        async move {
            let mut client = RawClient::connect(addr).await.unwrap();
            client.send(get("site.test", "/", "")).await.unwrap();
            client.read_response(false).await.unwrap().status
        }
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    apply(&proxy, &ntlm_config(&parent, "not-it")).await;
    assert_eq!(in_flight.await.unwrap(), 200);

    // When the response was done that connection went back to be kept. It must
    // not have been: the next request has to authenticate with what is
    // configured now, which the parent refuses.
    let response = ask(&proxy, get("site.test", "/", "")).await;
    assert_eq!(response.status, 502, "{}", response.body_text());
    assert_eq!(parent.connection_count(), 2);
}

#[tokio::test]
async fn unchanged_credentials_keep_the_pause_after_a_refusal() {
    let parent = account_parent().await;
    let config = ntlm_config(&parent, "wrong");
    let proxy = start_proxy(&config).await;
    assert_eq!(ask(&proxy, get("site.test", "/", "")).await.status, 502);
    assert_eq!(parent.messages(3), 1);

    // Reading the same configuration again is no reason to try the account again.
    apply(&proxy, &config).await;
    let response = ask(&proxy, get("site.test", "/", "")).await;
    assert_eq!(response.status, 503, "{}", response.body_text());
    assert_eq!(parent.messages(3), 1);
    assert!(response.headers.contains("retry-after"));
}

// ---- the PAC script ----

fn script_for(parent: &MockOrigin) -> String {
    format!(
        r#"function FindProxyForURL(url, host) {{ return "PROXY {}"; }}"#,
        parent.addr()
    )
}

fn pac_table(file: &std::path::Path, extra: &str) -> String {
    format!("[pac]\nfile = {:?}\n{extra}", file.display().to_string())
}

#[tokio::test]
async fn a_reload_reads_a_script_that_changed_without_waiting_for_its_time() {
    let (a, b) = (named("A").await, named("B").await);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy.pac");
    std::fs::write(&file, script_for(&a)).unwrap();
    // The script is looked at every hour, by default: only the reload can bring the change.
    let table = pac_table(&file, "refresh_secs = 3600\n");
    let proxy = start_proxy(&table).await;
    assert_eq!(answer(&proxy).await, "A");

    std::fs::write(&file, script_for(&b)).unwrap();
    apply(&proxy, &table).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while answer(&proxy).await != "B" {
        assert!(Instant::now() < deadline, "the new script never came");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_reload_can_name_another_script_and_a_script_that_fails_changes_nothing() {
    let (a, b) = (named("A").await, named("B").await);
    let dir = tempfile::tempdir().unwrap();
    let (first, second) = (dir.path().join("a.pac"), dir.path().join("b.pac"));
    std::fs::write(&first, script_for(&a)).unwrap();
    std::fs::write(&second, script_for(&b)).unwrap();
    let proxy = start_proxy(&pac_table(&first, "")).await;
    assert_eq!(answer(&proxy).await, "A");

    apply(&proxy, &pac_table(&second, "")).await;
    assert_eq!(answer(&proxy).await, "B");

    // A script that is missing, or does not load, is a reload that fails, and
    // the settings in use stay.
    for bad in [dir.path().join("missing.pac"), {
        let broken = dir.path().join("broken.pac");
        std::fs::write(&broken, "function FindProxyForURL(").unwrap();
        broken
    }] {
        let config = Config::from_toml_str(
            &format!("listen = [\"127.0.0.1:0\"]\n{}", pac_table(&bad, "")),
            Overrides::default(),
        )
        .unwrap();
        let error = proxy.reloader.apply(&config).await.unwrap_err().to_string();
        assert!(error.contains("cannot use the PAC file"), "{error}");
        assert_eq!(answer(&proxy).await, "B");
    }
}

#[tokio::test]
async fn a_script_that_cannot_be_fetched_at_a_reload_is_kept_from_before() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let parent = named("A").await;
    let script = script_for(&parent);
    let up = Arc::new(AtomicBool::new(true));
    let pac = MockOrigin::start({
        let up = up.clone();
        move |_| {
            if up.load(Ordering::SeqCst) {
                Reply::ok(&script)
            } else {
                Reply::raw("HTTP/1.1 503 Gone\r\nContent-Length: 0\r\n\r\n")
            }
        }
    })
    .await;
    let table = format!(
        "[pac]\nurl = \"http://{}/proxy.pac\"\nrefresh_secs = 3600\n",
        pac.authority()
    );
    let proxy = start_proxy(&table).await;
    assert_eq!(answer(&proxy).await, "A");

    // The address stops answering. Reading the same configuration again must
    // not lose the script that works, which is the last one there was.
    up.store(false, Ordering::SeqCst);
    apply(&proxy, &table).await;
    assert_eq!(answer(&proxy).await, "A");
}

// ---- what a reload cannot change ----

#[tokio::test]
async fn what_needs_a_restart_is_reported_and_left_as_it_was() {
    let origin = named("served").await;
    let proxy = start_proxy("").await;
    let before = proxy.addr;

    let pending = apply(
        &proxy,
        "[[tunnels]]\nlisten = \"127.0.0.1:0\"\ntarget = \"x.example.com:22\"\n\
         [socks5]\nlisten = [\"127.0.0.1:0\"]\n[log]\nlevel = \"debug\"\n",
    )
    .await;
    assert_eq!(pending, ["tunnels", "socks5.listen", "log.level"]);
    // Where it listens is where it listened, and nothing new listens.
    assert!(proxy.tunnels.is_empty() && proxy.socks5.is_empty());
    let mut client = RawClient::connect(before).await.unwrap();
    client
        .send(get(&origin.authority(), "/", ""))
        .await
        .unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 200);

    let other = Config::from_toml_str("listen = [\"127.0.0.1:1\"]", Overrides::default()).unwrap();
    assert_eq!(proxy.reloader.apply(&other).await.unwrap(), ["listen"]);
}

// ---- the SOCKS5 server ----

async fn socks_login(proxy: &TestProxy, user: &[u8], password: &[u8]) -> bool {
    let mut stream = TcpStream::connect(proxy.socks5[0]).await.unwrap();
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await.unwrap();
    assert_eq!(chosen, [5, 2]);
    let mut message = vec![1, u8::try_from(user.len()).unwrap()];
    message.extend(user);
    message.push(u8::try_from(password.len()).unwrap());
    message.extend(password);
    stream.write_all(&message).await.unwrap();
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    status == [1, 0]
}

#[tokio::test]
async fn a_new_password_for_the_socks5_server_is_asked_for_at_once() {
    let table = |password: &str| {
        format!(
            "[socks5]\nlisten = [\"127.0.0.1:0\"]\nusername = \"bob\"\npassword = \"{password}\"\n"
        )
    };
    let proxy = start_proxy(&table("first-one")).await;
    assert!(socks_login(&proxy, b"bob", b"first-one").await);

    assert_eq!(
        apply(&proxy, &table("second-one")).await,
        Vec::<&str>::new()
    );
    assert!(!socks_login(&proxy, b"bob", b"first-one").await);
    assert!(socks_login(&proxy, b"bob", b"second-one").await);
}
