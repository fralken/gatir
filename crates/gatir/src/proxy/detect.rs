//! `gatir detect`: probes a real, live parent proxy for what it offers, and,
//! when credentials are configured, which of them it accepts.
//!
//! Unlike [`crate::auth::diagnose`] (`gatir negotiate`), which only asks the
//! local system for a token and never opens a connection, everything here
//! talks to the parent over the network: a first, bare request to see whether
//! it asks for authentication at all and what it offers, then, only for the
//! scheme that matches the configured method and only if the parent offers
//! it, one real attempt per NTLM dialect (or one Negotiate attempt) to see
//! which is accepted. Each attempt is a real login against the account behind
//! the credentials, exactly as a real request would be: it is not repeated
//! automatically, and nothing here holds gatir's own parent away from a
//! rejection the way the live proxy does, since this runs once, by hand.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{HOST, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use hyper::{Method, Request, StatusCode, Uri, Version};

use super::body::{Body, full};
use super::failure::{Failure, connect_failure, try_connect};
use super::parent::{Outcome, ParentAuth, send};
use super::upstream::handshake;
use crate::auth::{TokenSource, offered_schemes};
use crate::config::{AuthMethod, Credentials, HostPort, Timeouts};

/// The NTLM dialects gatir can answer a challenge with, tried in this order:
/// the strongest first, stopping at the first the parent accepts.
const NTLM_DIALECTS: [AuthMethod; 3] = [AuthMethod::Ntlmv2, AuthMethod::Ntlm2sr, AuthMethod::Nt];

/// What the parent answered a bare, unauthenticated request with.
pub struct Probe {
    pub status: u16,
    /// The schemes its challenge offers, in the order it offered them; empty
    /// if it did not challenge the request at all.
    pub offers: Vec<String>,
}

/// One authentication scheme (an NTLM dialect, or Negotiate) tried for real
/// against the parent.
pub struct Attempt {
    /// `credentials.method`'s name: "ntlmv2", "ntlm2sr", "nt", or "negotiate".
    pub method: &'static str,
    pub outcome: AttemptOutcome,
}

pub enum AttemptOutcome {
    /// The parent accepted it: this request, and every one after it on the
    /// connection, went through.
    Accepted,
    /// The parent still refused after seeing the proof.
    Rejected,
    /// The attempt could not be carried out at all (a network problem, a
    /// dialect the configured secret cannot answer, a missing Kerberos
    /// ticket...): the text says why.
    Failed(String),
}

pub struct Report {
    pub probe: Probe,
    /// Empty when the probe needed no authentication, when no credentials are
    /// configured, or when the parent does not offer the configured scheme.
    pub attempts: Vec<Attempt>,
}

/// Probes `parent` for `url`, and, if `credentials` are given, tries them.
/// `tokens` replaces the system's Kerberos tickets for a Negotiate attempt,
/// for tests; `None` means the real system.
/// The error is already the message to show: `Failure`, which says it, is
/// private to this module and everything around it.
pub async fn run(
    parent: &HostPort,
    url: &Uri,
    credentials: Option<&Credentials>,
    timeouts: &Timeouts,
    tokens: Option<Arc<dyn TokenSource>>,
) -> Result<Report, String> {
    let probe = bare_probe(parent, url, timeouts)
        .await
        .map_err(|failure| failure.message())?;
    let mentions = |scheme: &str| {
        probe
            .offers
            .iter()
            .any(|offer| offer.eq_ignore_ascii_case(scheme))
    };

    let mut attempts = Vec::new();
    if probe.status == StatusCode::PROXY_AUTHENTICATION_REQUIRED.as_u16() {
        match credentials {
            Some(credentials) if credentials.method == AuthMethod::Negotiate => {
                if mentions("Negotiate") {
                    attempts.push(try_one(parent, url, credentials, timeouts, tokens).await);
                }
            }
            Some(credentials) if mentions("NTLM") => {
                for method in NTLM_DIALECTS {
                    let mut dialect = credentials.clone();
                    dialect.method = method;
                    let attempt = try_one(parent, url, &dialect, timeouts, tokens.clone()).await;
                    let accepted = matches!(attempt.outcome, AttemptOutcome::Accepted);
                    attempts.push(attempt);
                    if accepted {
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(Report { probe, attempts })
}

/// A single, bare, unauthenticated request: what it comes back with says
/// whether the parent needs authentication for this URL at all, and, if it
/// does, what it offers.
async fn bare_probe(parent: &HostPort, url: &Uri, timeouts: &Timeouts) -> Result<Probe, Failure> {
    let mut sender = connect(parent, timeouts.connect).await?;
    let response = send(&mut sender, request(url, None)?, timeouts.response).await?;
    let status = response.status().as_u16();
    let offers = offered_schemes(response.headers().get_all(PROXY_AUTHENTICATE));
    Ok(Probe { status, offers })
}

/// One real attempt: opens its own connection (NTLM and Negotiate both
/// authenticate the connection, not the request) and runs the whole exchange
/// [`ParentAuth::negotiate`] already knows how to run for the live proxy.
async fn try_one(
    parent: &HostPort,
    url: &Uri,
    credentials: &Credentials,
    timeouts: &Timeouts,
    tokens: Option<Arc<dyn TokenSource>>,
) -> Attempt {
    let outcome = 'outcome: {
        let auth = match ParentAuth::new(credentials, tokens) {
            Ok(auth) => auth,
            Err(err) => break 'outcome AttemptOutcome::Failed(err.to_string()),
        };
        let mut sender = match connect(parent, timeouts.connect).await {
            Ok(sender) => sender,
            Err(failure) => break 'outcome AttemptOutcome::Failed(failure.message()),
        };
        let carrier = || request(url, None).expect("a URL already used for the probe");
        let negotiated = auth
            .negotiate(
                &mut sender,
                carrier,
                &parent.host,
                timeouts.response,
                || Box::pin(connect(parent, timeouts.connect)),
            )
            .await;
        match negotiated {
            // A Negotiate ticket (or its NTLM-inside-Negotiate fallback) that
            // the parent turns down outright is an error from `negotiate`
            // itself, unlike NTLM, which always gets a proof to try on a
            // second request.
            Err(Failure::TicketRejected { .. } | Failure::SessionRejected { .. }) => {
                AttemptOutcome::Rejected
            }
            Err(failure) => AttemptOutcome::Failed(failure.message()),
            Ok(Outcome::Answered(_)) => AttemptOutcome::Accepted,
            Ok(Outcome::Proof { header, .. }) => {
                let proven = match request(url, Some(header)) {
                    Ok(proven) => proven,
                    Err(failure) => break 'outcome AttemptOutcome::Failed(failure.message()),
                };
                match send(&mut sender, proven, timeouts.response).await {
                    Err(failure) => AttemptOutcome::Failed(failure.message()),
                    Ok(response)
                        if response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED =>
                    {
                        AttemptOutcome::Rejected
                    }
                    Ok(_) => AttemptOutcome::Accepted,
                }
            }
        }
    };
    Attempt {
        method: credentials.method.as_str(),
        outcome,
    }
}

/// Connects to `parent` and starts the HTTP/1 client on it.
async fn connect(parent: &HostPort, limit: Duration) -> Result<SendRequest<Body>, Failure> {
    let address = parent.to_string();
    let stream = try_connect(&address, limit)
        .await
        .map_err(|err| connect_failure(&address, err))?;
    handshake(stream).await
}

/// A `GET` for `url`, in absolute form, as a real proxied request would send
/// it; `proof` becomes `Proxy-Authorization` when there is one.
fn request(url: &Uri, proof: Option<HeaderValue>) -> Result<Request<Body>, Failure> {
    let host = url
        .authority()
        .ok_or(Failure::BadRequest("the URL needs a host"))?
        .as_str();
    let host = HeaderValue::from_str(host).map_err(|_| Failure::BadRequest("invalid host"))?;
    let mut request = Request::new(full(Bytes::new()));
    *request.method_mut() = Method::GET;
    *request.uri_mut() = url.clone();
    *request.version_mut() = Version::HTTP_11;
    let headers = request.headers_mut();
    headers.insert(HOST, host);
    if let Some(proof) = proof {
        headers.insert(PROXY_AUTHORIZATION, proof);
    }
    Ok(request)
}
