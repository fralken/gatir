//! `gatir detect`: probing a real parent proxy (here, the mock) for what it
//! offers, and, with credentials configured, which of gatir's NTLM dialects
//! (or Negotiate) it accepts. Unlike the other proxy tests, there is no live
//! gatir proxy here: `detect` talks to the parent on its own.

use std::sync::Arc;
use std::time::Duration;

use gatir::auth::{AuthError, SecurityContext, TokenSource, single_token};
use gatir::config::{Config, Credentials, HostPort, Overrides, Timeouts};
use gatir::proxy::{AttemptOutcome, detect};
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::{MockOrigin, Reply};
use hyper::Uri;

const LIMIT: Duration = Duration::from_secs(5);

fn timeouts() -> Timeouts {
    Timeouts {
        connect: LIMIT,
        response: LIMIT,
        ..Timeouts::default()
    }
}

fn url() -> Uri {
    "http://example.com/".parse().unwrap()
}

fn addr_of(parent: &MockNtlmParent) -> HostPort {
    parent.addr().to_string().parse().unwrap()
}

fn addr_of_origin(origin: &MockOrigin) -> HostPort {
    origin.addr().to_string().parse().unwrap()
}

fn credentials(toml: &str) -> Credentials {
    Config::from_toml_str(toml, Overrides::default())
        .unwrap()
        .credentials
        .unwrap()
}

fn ntlmv2(user: &str, domain: &str, password: &str) -> Credentials {
    credentials(&format!(
        "[credentials]\nusername = \"{user}\"\ndomain = \"{domain}\"\npassword = \"{password}\"\n\
         method = \"ntlmv2\"\n"
    ))
}

fn negotiate_credentials() -> Credentials {
    credentials("[credentials]\nmethod = \"negotiate\"\n")
}

/// Negotiate credentials with a fixed service name, so the token the mock
/// parent is set up to accept does not depend on the ephemeral port it binds
/// to (`credentials.spn` overrides the default `HTTP@<parent host>`).
fn negotiate_credentials_for(spn: &str) -> Credentials {
    credentials(&format!(
        "[credentials]\nmethod = \"negotiate\"\nspn = \"{spn}\"\n"
    ))
}

fn well_behaved_parent() -> (Account, Options) {
    (Account::new("alice", "CORP", "s3cret"), Options::default())
}

fn reply(request: &gatir_testkit::http::Request) -> Reply {
    Reply::ok(&format!("{} bytes", request.body.len()))
}

/// Tokens that name the service they are for, like a real ticket would.
#[derive(Debug)]
struct Tickets;

impl TokenSource for Tickets {
    fn start(&self, service: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
        Ok(single_token(format!("ticket for {service}").into_bytes()))
    }
}

/// A user with no Kerberos ticket at all.
#[derive(Debug)]
struct NoTickets;

impl TokenSource for NoTickets {
    fn start(&self, service: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
        Err(AuthError::NoTicket {
            service: service.to_owned(),
            reason: "No Kerberos credentials available".to_owned(),
        })
    }
}

#[tokio::test]
async fn a_parent_that_needs_no_authentication_is_reported_as_such() {
    let origin = MockOrigin::start(|_request| Reply::ok("hello")).await;
    let report = detect(&addr_of_origin(&origin), &url(), None, &timeouts(), None)
        .await
        .unwrap();
    assert_eq!(report.probe.status, 200);
    assert!(report.probe.offers.is_empty());
    assert!(report.attempts.is_empty());
}

#[tokio::test]
async fn a_parent_that_offers_only_basic_is_reported_and_nothing_is_tried() {
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options {
            offers: vec!["Basic".to_owned()],
            ntlm: false,
            ..Options::default()
        },
        reply,
    )
    .await;

    let credentials = ntlmv2("alice", "CORP", "s3cret");
    let report = detect(
        &addr_of(&parent),
        &url(),
        Some(&credentials),
        &timeouts(),
        None,
    )
    .await
    .unwrap();

    assert_eq!(report.probe.status, 407);
    assert_eq!(report.probe.offers, ["Basic"]);
    assert!(report.attempts.is_empty());
}

#[tokio::test]
async fn no_credentials_configured_only_probes() {
    let (account, options) = well_behaved_parent();
    let parent = MockNtlmParent::start(account, options, reply).await;

    let report = detect(&addr_of(&parent), &url(), None, &timeouts(), None)
        .await
        .unwrap();

    assert_eq!(report.probe.status, 407);
    assert_eq!(report.probe.offers, ["NTLM"]);
    assert!(report.attempts.is_empty());
}

#[tokio::test]
async fn the_right_dialect_is_found_and_the_rest_are_not_tried() {
    let (account, options) = well_behaved_parent();
    let parent = MockNtlmParent::start(account, options, reply).await;

    let credentials = ntlmv2("alice", "CORP", "s3cret");
    let report = detect(
        &addr_of(&parent),
        &url(),
        Some(&credentials),
        &timeouts(),
        None,
    )
    .await
    .unwrap();

    assert_eq!(report.attempts.len(), 1);
    assert_eq!(report.attempts[0].method, "ntlmv2");
    assert!(matches!(
        report.attempts[0].outcome,
        AttemptOutcome::Accepted
    ));
}

#[tokio::test]
async fn a_wrong_password_is_rejected_for_every_dialect() {
    let (account, options) = well_behaved_parent();
    let parent = MockNtlmParent::start(account, options, reply).await;

    let credentials = ntlmv2("alice", "CORP", "wrong-password");
    let report = detect(
        &addr_of(&parent),
        &url(),
        Some(&credentials),
        &timeouts(),
        None,
    )
    .await
    .unwrap();

    let methods: Vec<_> = report
        .attempts
        .iter()
        .map(|attempt| attempt.method)
        .collect();
    assert_eq!(methods, ["ntlmv2", "ntlm2sr", "nt"]);
    assert!(
        report
            .attempts
            .iter()
            .all(|attempt| matches!(attempt.outcome, AttemptOutcome::Rejected))
    );
}

#[tokio::test]
async fn a_kerberos_ticket_the_parent_accepts_is_reported() {
    // A fixed service name (`credentials.spn`), so the token to accept does
    // not depend on the ephemeral port the mock parent binds to.
    const SERVICE: &str = "HTTP/parent.example@EXAMPLE.COM";
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options {
            offers: vec!["Negotiate".to_owned(), "NTLM".to_owned()],
            negotiate_token: Some(format!("ticket for {SERVICE}").into_bytes()),
            ..Options::default()
        },
        reply,
    )
    .await;

    let report = detect(
        &addr_of(&parent),
        &url(),
        Some(&negotiate_credentials_for(SERVICE)),
        &timeouts(),
        Some(Arc::new(Tickets)),
    )
    .await
    .unwrap();

    assert_eq!(report.attempts.len(), 1);
    assert_eq!(report.attempts[0].method, "negotiate");
    assert!(matches!(
        report.attempts[0].outcome,
        AttemptOutcome::Accepted
    ));
}

#[tokio::test]
async fn a_kerberos_ticket_the_parent_refuses_is_reported() {
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options {
            offers: vec!["Negotiate".to_owned(), "NTLM".to_owned()],
            // `None` refuses every Negotiate token.
            negotiate_token: None,
            ..Options::default()
        },
        reply,
    )
    .await;

    let report = detect(
        &addr_of(&parent),
        &url(),
        Some(&negotiate_credentials()),
        &timeouts(),
        Some(Arc::new(Tickets)),
    )
    .await
    .unwrap();

    assert_eq!(report.attempts.len(), 1);
    assert!(matches!(
        report.attempts[0].outcome,
        AttemptOutcome::Rejected
    ));
}

#[tokio::test]
async fn no_kerberos_ticket_is_reported_as_a_failed_attempt() {
    let parent = MockNtlmParent::start(
        Account::new("alice", "CORP", "s3cret"),
        Options {
            offers: vec!["Negotiate".to_owned(), "NTLM".to_owned()],
            negotiate_token: None,
            ..Options::default()
        },
        reply,
    )
    .await;

    let report = detect(
        &addr_of(&parent),
        &url(),
        Some(&negotiate_credentials()),
        &timeouts(),
        Some(Arc::new(NoTickets)),
    )
    .await
    .unwrap();

    assert_eq!(report.attempts.len(), 1);
    assert!(matches!(
        &report.attempts[0].outcome,
        AttemptOutcome::Failed(_)
    ));
}

#[tokio::test]
async fn negotiate_configured_against_a_parent_offering_only_ntlm_tries_nothing() {
    let (account, options) = well_behaved_parent();
    let parent = MockNtlmParent::start(account, options, reply).await;

    let report = detect(
        &addr_of(&parent),
        &url(),
        Some(&negotiate_credentials()),
        &timeouts(),
        Some(Arc::new(Tickets)),
    )
    .await
    .unwrap();

    assert!(report.attempts.is_empty());
}
