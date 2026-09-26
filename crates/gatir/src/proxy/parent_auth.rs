//! Authenticating connections to a parent proxy.
//!
//! Both schemes belong to the connection, so every new connection to the
//! parent is authenticated once, and a pooled one already is. They differ in
//! how the proof is made:
//!
//! - NTLM needs the proxy's challenge. [`ParentAuth::negotiate`] runs the first
//!   half of the exchange, and the caller then sends the real request carrying
//!   the proof it returns.
//! - Negotiate with Kerberos needs none: [`ParentAuth::begin`] makes the proof at
//!   once, and the real request carries it. When the system falls back to NTLM
//!   inside Negotiate, `begin` says so, and the exchange goes on as NTLM's does,
//!   through [`ParentAuth::negotiate`].
//!
//! Every attempt with wrong NTLM credentials counts as a failed logon against
//! the account, and a few of them lock it. So [`ParentAuth::admit`] lets one
//! attempt at a time through until the credentials have worked once, and
//! stays away from the parent for a while after it refuses them. A Kerberos
//! ticket that the proxy does not accept costs the account nothing, so
//! Negotiate is never held off.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{HeaderMap, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use hyper::{Request, Response, StatusCode};
use tokio::time::timeout;

use super::body::{Body, answer_within};
use super::failure::Failure;
use crate::auth::{
    AuthError, Authenticator, Refusal, SecurityContext, TokenSource, challenge, negotiate_header,
    refusal,
};
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

/// The parent's answer to the request that carried the first message.
pub(super) enum Outcome {
    /// The parent asked for no authentication: this is its answer.
    Answered(Response<Incoming>),
    /// The parent sent a challenge. The connection is ready for the real
    /// request, which must carry this `Proxy-Authorization` value.
    Proof {
        header: HeaderValue,
        /// The Kerberos service the proof was made for, with Negotiate.
        service: Option<String>,
    },
}

/// How the authentication of a connection begins.
pub(super) enum Begun {
    /// The proof is made and needs nothing from the parent: the real request
    /// carries it.
    Ready(DirectProof),
    /// The parent has to be asked first; [`ParentAuth::negotiate`] does it.
    Challenge(Pending),
}

/// What is kept between the first message and the answer to the challenge.
pub(super) enum Pending {
    Ntlm,
    Negotiate {
        context: Box<dyn SecurityContext>,
        /// The token that opens the exchange.
        first: Vec<u8>,
        service: String,
    },
}

/// Permission to try to authenticate, held until the parent has said whether
/// it accepts the proof.
pub(super) struct Admission<'a> {
    auth: &'a ParentAuth,
    _gate: Option<tokio::sync::MutexGuard<'a, ()>>,
    /// The Kerberos service the proof was made for, to say so if it is refused.
    service: Option<String>,
}

/// A proof made without a challenge.
pub(super) struct DirectProof {
    pub header: HeaderValue,
    /// The Kerberos service it was made for.
    pub service: String,
}

impl ParentAuth {
    /// `tokens` replaces the system's Kerberos tickets, for tests.
    pub(super) fn new(
        credentials: &Credentials,
        tokens: Option<Arc<dyn TokenSource>>,
    ) -> Result<Self, AuthError> {
        let authenticator = match tokens {
            Some(tokens) => Authenticator::with_tokens(credentials, tokens)?,
            None => Authenticator::new(credentials)?,
        };
        Ok(Self {
            authenticator,
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
                service: None,
            });
        }
        let gate = self.gate.lock().await;
        // The attempt ahead of this one may have settled the question.
        self.check()?;
        let gate = (!self.verified.load(Ordering::Acquire)).then_some(gate);
        Ok(Admission {
            auth: self,
            _gate: gate,
            service: None,
        })
    }

    /// Begins to authenticate a connection to the parent at `parent_host`.
    pub(super) async fn begin(&self, parent_host: &str, limit: Duration) -> Result<Begun, Failure> {
        let Authenticator::Negotiate(negotiate) = &self.authenticator else {
            return Ok(Begun::Challenge(Pending::Ntlm));
        };
        let service = negotiate.service_for(parent_host);
        let tokens = negotiate.tokens();
        let asked = service.clone();
        // A ticket for a new service is fetched from the KDC, which blocks.
        let (context, step) = timeout(
            limit,
            tokio::task::spawn_blocking(move || {
                let mut context = tokens.start(&asked)?;
                let step = context.step(None)?;
                Ok::<_, AuthError>((context, step))
            }),
        )
        .await
        .map_err(|_| Failure::ResponseTimeout("the Kerberos server"))?
        .map_err(|_| Failure::Parent("the Kerberos ticket could not be requested"))??;
        let token = step.token.ok_or_else(|| AuthError::NoTicket {
            service: service.clone(),
            reason: "the system produced no token".to_owned(),
        })?;
        if step.complete {
            Ok(Begun::Ready(DirectProof {
                header: negotiate_header(&token),
                service,
            }))
        } else {
            tracing::debug!(%service, "the system needs an answer from the parent to go on");
            Ok(Begun::Challenge(Pending::Negotiate {
                context,
                first: token,
                service,
            }))
        }
    }

    /// Sends `first`, adding the first message, and reads the answer.
    pub(super) async fn negotiate(
        &self,
        sender: &mut SendRequest<Body>,
        mut first: Request<Body>,
        pending: Pending,
        limit: Duration,
    ) -> Result<Outcome, Failure> {
        let (opening, ntlm) = match (&pending, &self.authenticator) {
            (Pending::Ntlm, Authenticator::Ntlm(ntlm)) => (ntlm.first()?, Some(ntlm)),
            (Pending::Negotiate { first: token, .. }, Authenticator::Negotiate(_)) => {
                (negotiate_header(token), None)
            }
            _ => {
                return Err(Failure::Parent(
                    "an exchange was started for a scheme that is not the configured one",
                ));
            }
        };
        first.headers_mut().insert(PROXY_AUTHORIZATION, opening);
        let response = answer_within(limit, sender.send_request(first))
            .await
            .ok_or(Failure::ResponseTimeout("the parent proxy"))?
            .map_err(Failure::Upstream)?;
        if response.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            return Ok(Outcome::Answered(response));
        }

        let (parts, body) = response.into_parts();
        let (header, service) = match pending {
            Pending::Ntlm => (
                ntlm.expect("NTLM was matched above")
                    .respond(parts.headers.get_all(PROXY_AUTHENTICATE))?,
                None,
            ),
            Pending::Negotiate {
                context, service, ..
            } => (
                answer_challenge(context, service.clone(), &parts.headers, limit).await?,
                Some(service),
            ),
        };
        if !reusable(body, sender, limit).await {
            return Err(Failure::Parent(
                "the parent proxy did not keep the connection open during authentication",
            ));
        }
        Ok(Outcome::Proof { header, service })
    }
}

/// The answer to the token a parent sent with its `407`, made by the security
/// context that made the first one.
async fn answer_challenge(
    mut context: Box<dyn SecurityContext>,
    service: String,
    headers: &HeaderMap,
    limit: Duration,
) -> Result<HeaderValue, Failure> {
    let Some(from_parent) = challenge(headers.get_all(PROXY_AUTHENTICATE)) else {
        // No token: the parent does not offer Negotiate, or it refused.
        return Err(match refusal(headers.get_all(PROXY_AUTHENTICATE)) {
            Refusal::NotOffered { offered } => {
                Failure::Authentication(AuthError::NegotiateNotOffered { offered })
            }
            Refusal::AnotherRound | Refusal::Rejected => Failure::TicketRejected { service },
        });
    };
    let step = timeout(
        limit,
        tokio::task::spawn_blocking(move || context.step(Some(&from_parent))),
    )
    .await
    .map_err(|_| Failure::ResponseTimeout("the Kerberos server"))?
    .map_err(|_| Failure::Parent("the answer to the parent's token could not be made"))??;
    let token = step.token.ok_or(AuthError::Exchange {
        service,
        reason: "the system had nothing to answer the parent's token with".to_owned(),
    })?;
    Ok(negotiate_header(&token))
}

impl Admission<'_> {
    /// Records the Kerberos service the proof was made for.
    pub(super) fn made_for(mut self, service: String) -> Self {
        self.service = Some(service);
        self
    }

    /// The parent accepted the proof.
    pub(super) fn accepted(self) {
        self.auth.verified.store(true, Ordering::Release);
        tracing::debug!("the parent proxy accepted the credentials");
    }

    /// The parent refused the proof; `fields` are the `Proxy-Authenticate`
    /// fields of its `407`. An NTLM refusal keeps gatir away from the parent
    /// for a while; a Negotiate one does not.
    pub(super) fn refused(self, fields: &HeaderMap) -> Failure {
        match &self.auth.authenticator {
            Authenticator::Ntlm(ntlm) => {
                let user = ntlm.user().to_owned();
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
            Authenticator::Negotiate(_) => {
                self.auth.verified.store(false, Ordering::Release);
                let service = self.service.clone().unwrap_or_default();
                match refusal(fields.get_all(PROXY_AUTHENTICATE)) {
                    Refusal::NotOffered { offered } => {
                        Failure::Authentication(AuthError::NegotiateNotOffered { offered })
                    }
                    Refusal::AnotherRound => Failure::Parent(
                        "the parent proxy answered the Negotiate token with a token of its own, \
                         and a second round is not supported yet",
                    ),
                    Refusal::Rejected => {
                        tracing::warn!(%service, "the parent proxy did not accept the Kerberos ticket");
                        Failure::TicketRejected { service }
                    }
                }
            }
        }
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
