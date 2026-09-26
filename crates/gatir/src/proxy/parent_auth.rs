//! Authenticating connections to a parent proxy.
//!
//! [`ParentAuth::negotiate`] runs the first half of an NTLM exchange on a
//! connection; the caller then sends the real request carrying the proof it
//! returns. NTLM belongs to the connection, so every new connection to the
//! parent goes through this once, and a pooled one is already authenticated.
//!
//! Every attempt with wrong credentials counts as a failed logon against the
//! account, and a few of them lock it. So [`ParentAuth::admit`] lets one
//! attempt at a time through until the credentials have worked once, and stays
//! away from the parent for a while after it refuses them.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use hyper::{Request, Response, StatusCode};
use tokio::time::timeout;

use super::body::{Body, answer_within};
use super::failure::Failure;
use crate::auth::{AuthError, Authenticator};
use crate::config::Credentials;

/// How long gatir stays away from a parent that refused the credentials.
pub(super) const COOLDOWN: Duration = Duration::from_secs(300);
/// The most of a `407` body that is read to reach the end of the message.
const DRAIN_LIMIT: usize = 64 * 1024;

pub(super) struct ParentAuth {
    authenticator: Authenticator,
    /// When the parent last refused the credentials.
    rejected_at: Mutex<Option<Instant>>,
    /// Whether the credentials have worked, and not been refused since.
    verified: AtomicBool,
    /// Held during an attempt while the credentials are not known to work.
    gate: tokio::sync::Mutex<()>,
}

/// The parent's answer to the request that carried the NEGOTIATE message.
pub(super) enum Outcome {
    /// The parent asked for no authentication: this is its answer.
    Answered(Response<Incoming>),
    /// The parent sent a challenge. The connection is ready for the real
    /// request, which must carry this `Proxy-Authorization` value.
    Proof(HeaderValue),
}

/// Permission to try to authenticate, held until the parent has said whether
/// it accepts the proof.
pub(super) struct Admission<'a> {
    auth: &'a ParentAuth,
    _gate: Option<tokio::sync::MutexGuard<'a, ()>>,
}

impl ParentAuth {
    pub(super) fn new(credentials: &Credentials) -> Result<Self, AuthError> {
        Ok(Self {
            authenticator: Authenticator::new(credentials)?,
            rejected_at: Mutex::new(None),
            verified: AtomicBool::new(false),
            gate: tokio::sync::Mutex::new(()),
        })
    }

    fn rejected_at(&self) -> MutexGuard<'_, Option<Instant>> {
        self.rejected_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Fails while the parent's refusal of the credentials is recent.
    pub(super) fn check(&self) -> Result<(), Failure> {
        match *self.rejected_at() {
            Some(at) if at.elapsed() < COOLDOWN => {
                Err(Failure::CoolingDown(COOLDOWN - at.elapsed()))
            }
            _ => Ok(()),
        }
    }

    /// Asks to authenticate a new connection.
    pub(super) async fn admit(&self) -> Result<Admission<'_>, Failure> {
        self.check()?;
        if self.verified.load(Ordering::Acquire) {
            return Ok(Admission {
                auth: self,
                _gate: None,
            });
        }
        let gate = self.gate.lock().await;
        // The attempt ahead of this one may have settled the question.
        self.check()?;
        let gate = (!self.verified.load(Ordering::Acquire)).then_some(gate);
        Ok(Admission {
            auth: self,
            _gate: gate,
        })
    }

    /// Sends `first`, adding the NEGOTIATE message, and reads the answer.
    pub(super) async fn negotiate(
        &self,
        sender: &mut SendRequest<Body>,
        mut first: Request<Body>,
        limit: Duration,
    ) -> Result<Outcome, Failure> {
        first
            .headers_mut()
            .insert(PROXY_AUTHORIZATION, self.authenticator.first()?);
        let response = answer_within(limit, sender.send_request(first))
            .await
            .ok_or(Failure::ResponseTimeout("the parent proxy"))?
            .map_err(Failure::Upstream)?;
        if response.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            return Ok(Outcome::Answered(response));
        }

        let (parts, body) = response.into_parts();
        let proof = self
            .authenticator
            .respond(parts.headers.get_all(PROXY_AUTHENTICATE))?;
        if !reusable(body, sender, limit).await {
            return Err(Failure::Parent(
                "the parent proxy did not keep the connection open during authentication",
            ));
        }
        Ok(Outcome::Proof(proof))
    }
}

impl Admission<'_> {
    /// The parent accepted the proof.
    pub(super) fn accepted(self) {
        self.auth.verified.store(true, Ordering::Release);
        tracing::debug!("the parent proxy accepted the credentials");
    }

    /// The parent refused the proof: stay away from it for a while.
    pub(super) fn refused(self) -> Failure {
        let user = self.auth.authenticator.user().to_owned();
        let mut rejected_at = self.auth.rejected_at();
        let first = rejected_at.is_none_or(|at| at.elapsed() >= COOLDOWN);
        *rejected_at = Some(Instant::now());
        self.auth.verified.store(false, Ordering::Release);
        if first {
            tracing::warn!(
                %user,
                cooldown_secs = COOLDOWN.as_secs(),
                "the parent proxy rejected the credentials; not trying again for a while"
            );
        }
        Failure::CredentialsRejected { user }
    }
}

/// Reads a response body to its end, so the connection can carry the next
/// request, and waits until it can. False if the body is too long to bother
/// with, the connection was closed, or it takes longer than `limit`.
pub(super) async fn reusable(
    body: Incoming,
    sender: &mut SendRequest<Body>,
    limit: Duration,
) -> bool {
    let drained = async {
        Limited::new(body, DRAIN_LIMIT).collect().await.is_ok() && sender.ready().await.is_ok()
    };
    timeout(limit, drained).await.unwrap_or(false)
}
