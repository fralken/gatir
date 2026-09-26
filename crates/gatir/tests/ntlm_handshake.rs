//! gatir's NTLM client against a mock parent proxy whose side of the exchange
//! was written independently, from the specification. Requests are written by
//! hand, so the exchange on the wire is exactly the one a proxy would see.

mod common;

use common::get;
use gatir::auth::NtlmAuthenticator;
use gatir::config::{Config, Overrides};
use gatir_testkit::http::{RawClient, Response};
use gatir_testkit::ntlm_parent::{Account, MockNtlmParent, Options};
use gatir_testkit::origin::Reply;
use hyper::header::HeaderValue;

const DESTINATION: &str = "origin.example.com";

fn authenticator(method: &str, password: &str) -> NtlmAuthenticator {
    let toml = format!(
        "[credentials]\nusername = \"alice\"\ndomain = \"CORP\"\npassword = \"{password}\"\n\
         method = \"{method}\"\n"
    );
    let config = Config::from_toml_str(&toml, Overrides::default()).unwrap();
    NtlmAuthenticator::new(&config.credentials.unwrap()).unwrap()
}

async fn parent(options: Options) -> MockNtlmParent {
    MockNtlmParent::start(Account::new("alice", "CORP", "s3cret"), options, |_| {
        Reply::ok("served")
    })
    .await
}

fn with_proof(proof: &HeaderValue) -> String {
    get(
        DESTINATION,
        "/",
        &format!("Proxy-Authorization: {}\r\n", proof.to_str().unwrap()),
    )
}

fn challenge_fields(response: &Response) -> Vec<HeaderValue> {
    response
        .headers
        .get_all("proxy-authenticate")
        .into_iter()
        .map(|field| HeaderValue::from_str(field).unwrap())
        .collect()
}

/// Runs the three-message exchange on `client` and returns the final response.
async fn authenticate(client: &mut RawClient, auth: &NtlmAuthenticator) -> Response {
    client
        .send(with_proof(&auth.first().unwrap()))
        .await
        .unwrap();
    let challenge = client.read_response(false).await.unwrap();
    assert_eq!(
        challenge.status, 407,
        "the NEGOTIATE message gets a challenge"
    );

    let proof = auth.respond(&challenge_fields(&challenge)).unwrap();
    client.send(with_proof(&proof)).await.unwrap();
    client.read_response(false).await.unwrap()
}

#[tokio::test]
async fn every_dialect_authenticates_against_an_independent_server() {
    for method in ["ntlmv2", "ntlm2sr", "nt"] {
        let parent = parent(Options::default()).await;
        let auth = authenticator(method, "s3cret");
        let mut client = RawClient::connect(parent.addr()).await.unwrap();

        let response = authenticate(&mut client, &auth).await;
        assert_eq!(response.status, 200, "{method}");
        assert_eq!(response.body_text(), "served", "{method}");

        // The connection is authenticated now: no more proof is needed.
        client.send(get(DESTINATION, "/next", "")).await.unwrap();
        let next = client.read_response(false).await.unwrap();
        assert_eq!(next.status, 200, "{method}: a second request");
        assert_eq!(parent.connection_count(), 1, "{method}");
        assert_eq!(parent.messages(1), 1, "{method}");
        assert_eq!(parent.messages(3), 1, "{method}");
    }
}

#[tokio::test]
async fn ntlmv2_uses_the_server_clock_and_echoes_its_target_info() {
    // The mock refuses an NTLMv2 blob that does not carry the timestamp and the
    // AV pairs it sent. A clock far from the real one shows the client uses it.
    let long_ago = 116_444_736_000_000_000; // 1970-01-01, as a FILETIME
    let parent = parent(Options {
        timestamp: Some(long_ago),
        ..Options::default()
    })
    .await;
    let mut client = RawClient::connect(parent.addr()).await.unwrap();

    let response = authenticate(&mut client, &authenticator("ntlmv2", "s3cret")).await;
    assert_eq!(response.status, 200);
}

#[tokio::test]
async fn a_wrong_password_is_refused_and_the_connection_stays_unauthenticated() {
    let parent = parent(Options::default()).await;
    let mut client = RawClient::connect(parent.addr()).await.unwrap();

    let response = authenticate(&mut client, &authenticator("ntlmv2", "not-the-password")).await;
    assert_eq!(response.status, 407);
    assert!(parent.served().is_empty());

    client.send(get(DESTINATION, "/", "")).await.unwrap();
    assert_eq!(client.read_response(false).await.unwrap().status, 407);
    assert!(parent.served().is_empty());
}

#[tokio::test]
async fn a_proof_made_for_one_connection_is_useless_on_another() {
    let parent = parent(Options::default()).await;
    let auth = authenticator("ntlmv2", "s3cret");

    // Answer the challenge of the first connection...
    let mut first = RawClient::connect(parent.addr()).await.unwrap();
    first
        .send(with_proof(&auth.first().unwrap()))
        .await
        .unwrap();
    let challenge = first.read_response(false).await.unwrap();
    let proof = auth.respond(&challenge_fields(&challenge)).unwrap();

    // ...and present the answer on a second one, which sent its own NEGOTIATE.
    let mut second = RawClient::connect(parent.addr()).await.unwrap();
    second
        .send(with_proof(&auth.first().unwrap()))
        .await
        .unwrap();
    assert_eq!(second.read_response(false).await.unwrap().status, 407);
    second.send(with_proof(&proof)).await.unwrap();
    assert_eq!(second.read_response(false).await.unwrap().status, 407);
    assert!(parent.served().is_empty());

    // The first connection still accepts it.
    first.send(with_proof(&proof)).await.unwrap();
    assert_eq!(first.read_response(false).await.unwrap().status, 200);
}

#[tokio::test]
async fn a_parent_without_ntlm_is_reported_with_the_schemes_it_offers() {
    let parent = parent(Options {
        ntlm: false,
        offers: vec!["Basic realm=\"corp\"".to_owned(), "Negotiate".to_owned()],
        ..Options::default()
    })
    .await;
    let auth = authenticator("ntlmv2", "s3cret");
    let mut client = RawClient::connect(parent.addr()).await.unwrap();

    client
        .send(with_proof(&auth.first().unwrap()))
        .await
        .unwrap();
    let refusal = client.read_response(false).await.unwrap();
    assert_eq!(refusal.status, 407);

    let error = auth.respond(&challenge_fields(&refusal)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "the parent proxy does not offer NTLM authentication (it offers: Basic, Negotiate)"
    );
}

#[tokio::test]
async fn a_request_without_proof_is_told_to_use_ntlm() {
    let parent = parent(Options::default()).await;
    let mut client = RawClient::connect(parent.addr()).await.unwrap();

    client.send(get(DESTINATION, "/", "")).await.unwrap();
    let response = client.read_response(false).await.unwrap();
    assert_eq!(response.status, 407);
    assert_eq!(response.headers.get("proxy-authenticate"), Some("NTLM"));
}
