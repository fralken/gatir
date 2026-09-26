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
//! - A parent that offers NTLM and not Negotiate answers the first Negotiate
//!   token with a `407` that names only NTLM. If the system can do NTLM by
//!   itself (Windows can), `negotiate` starts that exchange on the same
//!   connection, with the identity of the logged-on user: no password is
//!   configured, and the messages go with the `NTLM` scheme.
//!
//! Every attempt with wrong NTLM credentials counts as a failed logon against
//! the account, and a few of them lock it. So [`ParentAuth::admit`] lets one
//! attempt at a time through until the credentials have worked once, and
//! stays away from the parent for a while after it refuses them. What the
//! system answers a challenge with is NTLM too, made from the password of the
//! logged-on user (a stale one, after a change elsewhere, is the usual cause of
//! a refusal), so it is held off in the same way. A Kerberos ticket that the
//! proxy does not accept costs the account nothing, so it never is.

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
    ntlm, refusal,
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
        /// What the proof was made from, with Negotiate.
        made: Option<Made>,
    },
}

/// What a Negotiate proof was made from, which says what it means if the
/// parent refuses it.
pub(super) enum Made {
    /// A Kerberos ticket for this service.
    Ticket(String),
    /// The password of the logged-on user, which the system holds, answering an
    /// NTLM challenge (inside Negotiate or not); made for this service. As with
    /// a configured password, a wrong one can lock the account.
    Session(String),
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
    /// What the proof was made from, to say so if it is refused.
    made: Option<Made>,
}

/// A proof made without a challenge.
pub(super) struct DirectProof {
    pub header: HeaderValue,
    /// The Kerberos ticket it stands on.
    pub made: Made,
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

    /// Notes that the parent refused the credentials of `whose`: gatir stays
    /// away from it for a while.
    fn hold_off(&self, whose: &str) {
        let mut rejected_at = self.rejected_at();
        let first = rejected_at.is_none_or(|at| at.elapsed() >= COOLDOWN);
        *rejected_at = Some(Instant::now());
        self.verified.store(false, Ordering::Release);
        if first {
            tracing::warn!(
                user = %whose,
                cooldown_secs = COOLDOWN.as_secs(),
                "the parent proxy rejected the credentials; not trying again for a while"
            );
        }
    }

    /// Asks to authenticate a new connection.
    pub(super) async fn admit(&self) -> Result<Admission<'_>, Failure> {
        self.check()?;
        if self.verified.load(Ordering::Acquire) {
            return Ok(Admission {
                auth: self,
                _gate: None,
                made: None,
            });
        }
        let gate = self.gate.lock().await;
        // The attempt ahead of this one may have settled the question.
        self.check()?;
        let gate = (!self.verified.load(Ordering::Acquire)).then_some(gate);
        Ok(Admission {
            auth: self,
            _gate: gate,
            made: None,
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
                made: Made::Ticket(service),
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

    /// Sends the carrier request with the first message added, and reads the
    /// answer. A second carrier is made if the exchange has to start over in
    /// NTLM, so `carrier` makes one each time it is called.
    pub(super) async fn negotiate(
        &self,
        sender: &mut SendRequest<Body>,
        carrier: impl Fn() -> Request<Body>,
        pending: Pending,
        limit: Duration,
    ) -> Result<Outcome, Failure> {
        let (opening, ntlm, tokens) = match (&pending, &self.authenticator) {
            (Pending::Ntlm, Authenticator::Ntlm(ntlm)) => (ntlm.first()?, Some(ntlm), None),
            (Pending::Negotiate { first: token, .. }, Authenticator::Negotiate(negotiate)) => {
                (negotiate_header(token), None, Some(negotiate.tokens()))
            }
            _ => {
                return Err(Failure::Parent(
                    "an exchange was started for a scheme that is not the configured one",
                ));
            }
        };
        let mut first = carrier();
        first.headers_mut().insert(PROXY_AUTHORIZATION, opening);
        let response = send(sender, first, limit).await?;
        if response.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            return Ok(Outcome::Answered(response));
        }

        let (parts, body) = response.into_parts();
        // Copied, so that nothing of `pending` is borrowed across the awaits.
        let for_ntlm = match (&pending, tokens) {
            (Pending::Negotiate { service, .. }, Some(tokens)) => Some((service.clone(), tokens)),
            _ => None,
        };
        if let Some((service, tokens)) = for_ntlm
            && offers_only_ntlm(&parts.headers)
            && let Some((context, opening)) = start_system_ntlm(tokens, &service, limit).await?
        {
            let exchange = SystemNtlm {
                context,
                opening,
                service,
            };
            return ntlm_from_system(sender, carrier, exchange, body, limit).await;
        }

        let (header, made) = match pending {
            Pending::Ntlm => (
                ntlm.expect("NTLM was matched above")
                    .respond(parts.headers.get_all(PROXY_AUTHENTICATE))?,
                None,
            ),
            // The parent answered the token with one of its own: the system
            // has fallen back to NTLM.
            Pending::Negotiate {
                context, service, ..
            } => (
                answer_challenge(context, service.clone(), &parts.headers, limit).await?,
                Some(Made::Session(service)),
            ),
        };
        if !reusable(body, sender, limit).await {
            return Err(Failure::Parent(
                "the parent proxy did not keep the connection open during authentication",
            ));
        }
        Ok(Outcome::Proof { header, made })
    }
}

/// Sends a request and reads the head of the answer.
async fn send(
    sender: &mut SendRequest<Body>,
    request: Request<Body>,
    limit: Duration,
) -> Result<Response<Incoming>, Failure> {
    answer_within(limit, sender.send_request(request))
        .await
        .ok_or(Failure::ResponseTimeout("the parent proxy"))?
        .map_err(Failure::Upstream)
}

/// Whether the parent's `407` offers NTLM and not Negotiate, which is when the
/// NTLM of the system is worth a try.
fn offers_only_ntlm(headers: &HeaderMap) -> bool {
    match refusal(headers.get_all(PROXY_AUTHENTICATE)) {
        Refusal::NotOffered { offered } => offered
            .iter()
            .any(|scheme| scheme.eq_ignore_ascii_case("NTLM")),
        Refusal::AnotherRound | Refusal::Rejected => false,
    }
}

/// An NTLM exchange that the system has begun: the first message is made, and
/// the context holds what the answer to the challenge needs.
struct SystemNtlm {
    context: Box<dyn SecurityContext>,
    /// The NEGOTIATE message.
    opening: Vec<u8>,
    service: String,
}

/// Asks the system to begin an NTLM exchange for `service`. `None` if it
/// cannot do NTLM by itself.
async fn start_system_ntlm(
    tokens: Arc<dyn TokenSource>,
    service: &str,
    limit: Duration,
) -> Result<Option<(Box<dyn SecurityContext>, Vec<u8>)>, Failure> {
    let asked = service.to_owned();
    let started = timeout(
        limit,
        tokio::task::spawn_blocking(move || {
            let Some(mut context) = tokens.start_ntlm(&asked)? else {
                return Ok(None);
            };
            let opening = context
                .step(None)?
                .token
                .ok_or_else(|| AuthError::NoTicket {
                    service: asked,
                    reason: "the system produced no NTLM message".to_owned(),
                })?;
            Ok::<_, AuthError>(Some((context, opening)))
        }),
    )
    .await
    .map_err(|_| Failure::ResponseTimeout("the system's NTLM"))?
    .map_err(|_| Failure::Parent("the NTLM message could not be made"))??;
    Ok(started)
}

/// Carries out an NTLM exchange with the parent that the system has begun, on
/// the connection where the parent has just refused a Negotiate token.
/// `refused` is the body of that `407`.
async fn ntlm_from_system(
    sender: &mut SendRequest<Body>,
    carrier: impl Fn() -> Request<Body>,
    exchange: SystemNtlm,
    refused: Incoming,
    limit: Duration,
) -> Result<Outcome, Failure> {
    let SystemNtlm {
        mut context,
        opening,
        service,
    } = exchange;
    tracing::debug!(
        %service,
        "the parent proxy offers NTLM and not Negotiate: using the NTLM of the system, \
         with the identity of the logged-on user"
    );
    let stays_open = "the parent proxy did not keep the connection open during authentication";
    if !reusable(refused, sender, limit).await {
        return Err(Failure::Parent(stays_open));
    }

    let mut first = carrier();
    first
        .headers_mut()
        .insert(PROXY_AUTHORIZATION, ntlm::header(&opening));
    let response = send(sender, first, limit).await?;
    if response.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        return Ok(Outcome::Answered(response));
    }

    let (parts, body) = response.into_parts();
    let from_parent = ntlm::challenge(parts.headers.get_all(PROXY_AUTHENTICATE))?;
    let asked = service.clone();
    let step = timeout(
        limit,
        tokio::task::spawn_blocking(move || context.step(Some(&from_parent))),
    )
    .await
    .map_err(|_| Failure::ResponseTimeout("the system's NTLM"))?
    .map_err(|_| Failure::Parent("the answer to the NTLM challenge could not be made"))??;
    let token = step.token.ok_or(AuthError::Exchange {
        service: asked,
        reason: "the system had nothing to answer the NTLM challenge with".to_owned(),
    })?;
    if !reusable(body, sender, limit).await {
        return Err(Failure::Parent(stays_open));
    }
    Ok(Outcome::Proof {
        header: ntlm::header(&token),
        made: Some(Made::Session(service)),
    })
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
    /// Records what the proof was made from.
    pub(super) fn made_from(mut self, made: Option<Made>) -> Self {
        self.made = made;
        self
    }

    /// The parent accepted the proof.
    pub(super) fn accepted(self) {
        self.auth.verified.store(true, Ordering::Release);
        tracing::debug!("the parent proxy accepted the credentials");
    }

    /// The parent refused the proof; `fields` are the `Proxy-Authenticate`
    /// fields of its `407`. A refusal of a password-derived proof (NTLM,
    /// configured or of the system) keeps gatir away from the parent for a
    /// while; one of a Kerberos ticket does not.
    pub(super) fn refused(self, fields: &HeaderMap) -> Failure {
        match (&self.auth.authenticator, &self.made) {
            (Authenticator::Ntlm(ntlm), _) => {
                let user = ntlm.user().to_owned();
                self.auth.hold_off(&user);
                Failure::CredentialsRejected { user }
            }
            (Authenticator::Negotiate(_), Some(Made::Session(service))) => {
                self.auth.hold_off("the logged-on user");
                Failure::SessionRejected {
                    service: service.clone(),
                }
            }
            (Authenticator::Negotiate(_), made) => {
                self.auth.verified.store(false, Ordering::Release);
                let service = match made {
                    Some(Made::Ticket(service)) => service.clone(),
                    _ => String::new(),
                };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn offers(fields: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for field in fields {
            headers.append(PROXY_AUTHENTICATE, HeaderValue::from_str(field).unwrap());
        }
        headers
    }

    #[test]
    fn the_ntlm_of_the_system_is_for_a_parent_that_offers_ntlm_and_not_negotiate() {
        assert!(offers_only_ntlm(&offers(&["NTLM"])));
        assert!(offers_only_ntlm(&offers(&["Basic realm=\"x\"", "ntlm"])));
        // Negotiate is offered, and is what the system speaks best.
        assert!(!offers_only_ntlm(&offers(&["Negotiate", "NTLM"])));
        assert!(!offers_only_ntlm(&offers(&["Negotiate YIIB"])));
        assert!(!offers_only_ntlm(&offers(&["Basic realm=\"x\""])));
        assert!(!offers_only_ntlm(&offers(&[])));
    }
}
