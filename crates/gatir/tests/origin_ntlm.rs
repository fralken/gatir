//! NTLM straight to an origin server (`401`, `WWW-Authenticate`), for a host
//! named in `credentials.origin_hosts`: no parent is configured, so the origin
//! is reached directly, the way an intranet site behind no `no_proxy` entry
//! would be.

mod common;

use common::*;
use gatir_testkit::http::Response;
use gatir_testkit::ntlm_origin::MockNtlmOrigin;
use gatir_testkit::ntlm_parent::Account;
use gatir_testkit::origin::Reply;

async fn origin_with(account: Account) -> MockNtlmOrigin {
    MockNtlmOrigin::start(account, |request| {
        Reply::ok(&format!("{} {} bytes", request.method, request.body.len()))
    })
    .await
}

/// The configuration of a proxy with no parent, so `origin` is reached
/// directly, and NTLM answers its challenge too.
fn config(origin: &MockNtlmOrigin) -> String {
    format!(
        "[credentials]\nusername = \"alice\"\ndomain = \"CORP\"\npassword = \"s3cret\"\n\
         origin_hosts = [\"{}\"]\n",
        origin.addr().ip()
    )
}

async fn ask(proxy: &TestProxy, origin: &MockNtlmOrigin, path: &str) -> Response {
    let request = get(&origin.addr().to_string(), path, "");
    let mut client = gatir_testkit::http::RawClient::connect(proxy.addr)
        .await
        .unwrap();
    client.send(request).await.unwrap();
    client.read_response(false).await.unwrap()
}

#[tokio::test]
async fn a_probe_opens_the_exchange_then_the_real_request_carries_the_proof() {
    let origin = origin_with(Account::new("alice", "CORP", "s3cret")).await;
    let proxy = start_proxy(&config(&origin)).await;

    let response = ask(&proxy, &origin, "/page").await;
    assert_eq!(response.status, 200, "{}", response.body_text());
    assert_eq!(response.body_text(), "GET 0 bytes");

    // Making the opening message costs nothing (no network call), so it goes
    // out with the first request straight away, exactly as it does with NTLM
    // to a parent.
    let seen = origin.requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].message, Some(1));
    assert!(!seen[0].served);
    assert_eq!(seen[1].message, Some(3));
    assert!(seen[1].served);
    assert_eq!(seen[0].connection, seen[1].connection);
}

#[tokio::test]
async fn a_host_not_listed_is_left_to_answer_for_itself() {
    let origin = origin_with(Account::new("alice", "CORP", "s3cret")).await;
    // origin_hosts names a different address: gatir never offers credentials here.
    let proxy = start_proxy(
        "[credentials]\nusername = \"alice\"\ndomain = \"CORP\"\npassword = \"s3cret\"\n\
         origin_hosts = [\"198.51.100.1\"]\n",
    )
    .await;

    let response = ask(&proxy, &origin, "/").await;
    assert_eq!(response.status, 401);
    let seen = origin.requests();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].message.is_none() && !seen[0].served);
}

#[tokio::test]
async fn the_connection_stays_authenticated_for_the_requests_after() {
    let origin = origin_with(Account::new("alice", "CORP", "s3cret")).await;
    let proxy = start_proxy(&config(&origin)).await;

    for path in ["/one", "/two", "/three"] {
        assert_eq!(ask(&proxy, &origin, path).await.status, 200);
    }

    assert_eq!(origin.connection_count(), 1);
    let seen = origin.requests();
    assert_eq!(seen.len(), 4);
    assert_eq!(seen.iter().filter(|s| s.served).count(), 3);
}

#[tokio::test]
async fn a_wrong_password_is_reported_and_not_tried_again_for_a_while() {
    let origin = origin_with(Account::new("alice", "CORP", "s3cret")).await;
    // The configured password does not match the one the origin knows.
    let proxy =
        start_proxy(&config(&origin).replace("password = \"s3cret\"", "password = \"stale\""))
            .await;

    let response = ask(&proxy, &origin, "/").await;
    assert_eq!(response.status, 502);
    let text = response.body_text();
    assert!(
        text.contains("rejected the credentials of alice")
            && text.contains("credentials.origin_hosts"),
        "{text}"
    );
    let tried = origin.requests().len();
    assert_eq!(tried, 2);

    let response = ask(&proxy, &origin, "/").await;
    assert_eq!(response.status, 503);
    assert_eq!(origin.requests().len(), tried, "nothing more goes out");
}

#[tokio::test]
async fn negotiate_has_no_secret_to_answer_an_origin_with() {
    // credentials.origin_hosts needs an NTLM secret at configuration time.
    let origin = origin_with(Account::new("alice", "CORP", "s3cret")).await;
    let ip = origin.addr().ip().to_string();
    let toml = format!("[credentials]\nmethod = \"negotiate\"\norigin_hosts = [\"{ip}\"]\n");
    let config = gatir::config::Config::from_toml_str(&toml, gatir::config::Overrides::default());
    assert!(
        config
            .unwrap_err()
            .to_string()
            .contains("needs an NTLM secret")
    );
}
