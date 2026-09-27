//! Authenticating connections to a parent proxy.
//!
//! Both schemes belong to the connection, so every new connection to the
//! parent is authenticated once, and a pooled one already is. The first thing
//! sent on a new connection is never a credential the parent has not asked
//! for: a PAC script may well choose a parent that needs none at all (a purely
//! local relay, say), and both schemes let such a request through
//! unauthenticated, though for different reasons:
//!
//! - NTLM has nothing to lose by attaching its opening message to the first
//!   request straight away: making it costs nothing (no network call), and a
//!   parent that never asks for it just ignores it. [`ParentAuth::negotiate`]
//!   attaches it, and the parent's answer says whether more is needed.
//! - Negotiate is different: making its opening message may mean asking the
//!   system for a Kerberos ticket, a real request to the KDC that can fail
//!   outright for a destination that was never going to need one (an address
//!   with no realm, say). So the first request of a Negotiate exchange is
//!   sent bare, and the system is asked for a token only once the parent's
//!   `407` says it wants one.
//! - A parent that offers NTLM and not Negotiate says so in that same first
//!   `407`, before any token was ever built. If the system can do NTLM by
//!   itself (Windows can), `negotiate` starts that exchange instead, with the
//!   identity of the logged-on user: no password is configured, and the
//!   messages go with the `NTLM` scheme.
//!
//! [`ParentAuth::negotiate_origin`] is a third, narrower exchange: with a
//! server reached directly (never through a parent, and never through a
//! `CONNECT` tunnel, which gatir cannot see inside), named in
//! `credentials.origin_hosts`, that asks for NTLM itself (`401`,
//! `WWW-Authenticate`), the way an intranet site with Windows-integrated
//! authentication does. It reuses the same configured NTLM identity: Negotiate
//! has no password to answer such a challenge with, so it does not apply.
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
use hyper::header::{
    AUTHORIZATION, HeaderMap, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
    WWW_AUTHENTICATE,
};
use hyper::{Request, Response, StatusCode};
use tokio::time::timeout;

use super::body::{Body, answer_within};
use super::failure::Failure;
use crate::auth::{
    AuthError, Authenticator, Refusal, SecurityContext, TokenSource, challenge, negotiate_header,
    ntlm, refusal,
};
use crate::config::Credentials;
use crate::noproxy::NoProxy;

/// How long gatir stays away from a parent that refused the credentials.
pub(super) const COOLDOWN: Duration = Duration::from_secs(300);
/// The most of a `407` body that is read to reach the end of the message.
const DRAIN_LIMIT: usize = 64 * 1024;

pub(super) struct ParentAuth {
    authenticator: Authenticator,
    /// Origin servers this may also answer an NTLM challenge from directly.
    origin_hosts: NoProxy,
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
        /// The service it was made for, with Negotiate: the password of the
        /// logged-on user, which the system holds, answers an NTLM challenge
        /// (inside Negotiate or not) for this service. As with a configured
        /// password, a wrong one can lock the account. A Kerberos ticket that
        /// needed no such answer never reaches here: see the module doc.
        made: Option<String>,
    },
}

/// What is tried on a new connection, decided from the configured method
/// alone: nothing here has touched the system or the network yet.
pub(super) enum Pending {
    Ntlm,
    /// The service to ask a Kerberos ticket for, once the parent's first
    /// answer says it wants one.
    Negotiate {
        service: String,
    },
}

/// Permission to try to authenticate, held until the parent has said whether
/// it accepts the proof.
pub(super) struct Admission<'a> {
    auth: &'a ParentAuth,
    _gate: Option<tokio::sync::MutexGuard<'a, ()>>,
    /// The service a Negotiate proof was made for, to say so if it is refused.
    made: Option<String>,
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
            origin_hosts: credentials.origin_hosts.clone(),
            rejected_at: Mutex::new(None),
            verified: AtomicBool::new(false),
            gate: tokio::sync::Mutex::new(()),
        })
    }

    /// The configured NTLM identity, if `host` is one of the origin servers it
    /// also answers a direct challenge from. `None` for Negotiate, which has no
    /// password to answer one with, and for any host not named.
    pub(super) fn ntlm_for_origin(&self, host: &str) -> Option<&ntlm::Authenticator> {
        match &self.authenticator {
            Authenticator::Ntlm(ntlm) if self.origin_hosts.matches(host) => Some(ntlm),
            _ => None,
        }
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

    /// Decides what to try on a new connection to the parent at `parent_host`,
    /// from the configured method alone: nothing is asked of the system yet.
    pub(super) fn begin(&self, parent_host: &str) -> Pending {
        match &self.authenticator {
            Authenticator::Ntlm(_) => Pending::Ntlm,
            Authenticator::Negotiate(negotiate) => Pending::Negotiate {
                service: negotiate.service_for(parent_host),
            },
        }
    }

    /// Runs the exchange on a new connection, and reads the parent's answer.
    /// `carrier` makes a fresh copy of what is sent each time it is called (a
    /// probe, or the real request when it is safe to repeat): the exchange may
    /// need it more than once.
    pub(super) async fn negotiate(
        &self,
        sender: &mut SendRequest<Body>,
        carrier: impl Fn() -> Request<Body>,
        pending: Pending,
        limit: Duration,
    ) -> Result<Outcome, Failure> {
        // NTLM has nothing to lose by opening with its own message: making one
        // costs nothing, and a parent that never asks for it just ignores it.
        // Negotiate may have to ask the system for a Kerberos ticket, a real
        // request to the KDC, so it asks for nothing until the parent does.
        let opening = match &pending {
            Pending::Ntlm => {
                let Authenticator::Ntlm(ntlm) = &self.authenticator else {
                    return Err(Failure::Parent(
                        "an exchange was started for a scheme that is not the configured one",
                    ));
                };
                Some(ntlm.first()?)
            }
            Pending::Negotiate { .. } => None,
        };
        let mut first = carrier();
        if let Some(opening) = opening {
            first.headers_mut().insert(PROXY_AUTHORIZATION, opening);
        }
        let response = send(sender, first, limit).await?;
        if response.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            return Ok(Outcome::Answered(response));
        }
        let (parts, body) = response.into_parts();

        match pending {
            Pending::Ntlm => {
                let Authenticator::Ntlm(ntlm) = &self.authenticator else {
                    unreachable!("matched above");
                };
                let header = ntlm.respond(parts.headers.get_all(PROXY_AUTHENTICATE))?;
                if !reusable(body, sender, limit).await {
                    return Err(Failure::Parent(
                        "the parent proxy did not keep the connection open during authentication",
                    ));
                }
                Ok(Outcome::Proof { header, made: None })
            }
            Pending::Negotiate { service } => {
                let Authenticator::Negotiate(negotiate) = &self.authenticator else {
                    unreachable!("matched above");
                };
                if offers_only_ntlm(&parts.headers) {
                    let Some((context, opening)) =
                        start_system_ntlm(negotiate.tokens(), &service, limit).await?
                    else {
                        return Err(Failure::Authentication(AuthError::NegotiateNotOffered {
                            offered: offered_schemes(&parts.headers),
                        }));
                    };
                    let exchange = SystemNtlm {
                        context,
                        opening,
                        service,
                    };
                    return ntlm_from_system(sender, carrier, exchange, body, limit).await;
                }

                // Negotiate is offered: only now does the system make a ticket.
                tracing::debug!(%service, "the parent proxy offers Negotiate: asking the system for a ticket");
                let (context, header) =
                    first_ticket(negotiate.tokens(), service.clone(), limit).await?;
                if !reusable(body, sender, limit).await {
                    return Err(Failure::Parent(
                        "the parent proxy did not keep the connection open during authentication",
                    ));
                }

                let mut second = carrier();
                second.headers_mut().insert(PROXY_AUTHORIZATION, header);
                let response = send(sender, second, limit).await?;
                if response.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    return Ok(Outcome::Answered(response));
                }
                let (parts, body) = response.into_parts();
                // The parent answered the ticket with a token of its own: the
                // system needs another round to go on (NTLM inside Negotiate).
                let header =
                    answer_challenge(context, service.clone(), &parts.headers, limit).await?;
                if !reusable(body, sender, limit).await {
                    return Err(Failure::Parent(
                        "the parent proxy did not keep the connection open during authentication",
                    ));
                }
                Ok(Outcome::Proof {
                    header,
                    made: Some(service),
                })
            }
        }
    }
}

/// The exchange with an origin server that asks for NTLM itself
/// (`401`/`WWW-Authenticate`), reusing the configured identity: there is no
/// ticket to ask the system for, so, unlike [`ParentAuth::negotiate`], there
/// is only ever one scheme and one shape to this exchange.
pub(super) async fn negotiate_origin(
    ntlm: &ntlm::Authenticator,
    sender: &mut SendRequest<Body>,
    carrier: impl Fn() -> Request<Body>,
    limit: Duration,
) -> Result<Outcome, Failure> {
    let mut first = carrier();
    first.headers_mut().insert(AUTHORIZATION, ntlm.first()?);
    let response = send(sender, first, limit).await?;
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(Outcome::Answered(response));
    }
    let (parts, body) = response.into_parts();
    let header = ntlm.respond(parts.headers.get_all(WWW_AUTHENTICATE))?;
    if !reusable(body, sender, limit).await {
        return Err(Failure::Parent(
            "the origin server did not keep the connection open during authentication",
        ));
    }
    Ok(Outcome::Proof { header, made: None })
}

/// Asks the system for the first Kerberos token for `service`, now that the
/// parent has said it wants Negotiate: the security context, to answer a
/// second round with, and the header the token goes in.
async fn first_ticket(
    tokens: Arc<dyn TokenSource>,
    service: String,
    limit: Duration,
) -> Result<(Box<dyn SecurityContext>, HeaderValue), Failure> {
    let asked = service.clone();
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
        service,
        reason: "the system produced no token".to_owned(),
    })?;
    Ok((context, negotiate_header(&token)))
}

/// The schemes named in the `407` of `headers`, for a message saying what a
/// parent that does not offer Negotiate does offer.
fn offered_schemes(headers: &HeaderMap) -> Vec<String> {
    match refusal(headers.get_all(PROXY_AUTHENTICATE)) {
        Refusal::NotOffered { offered } => offered,
        Refusal::AnotherRound | Refusal::Rejected => Vec::new(),
    }
}

/// Sends a request and reads the head of the answer.
pub(super) async fn send(
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
        made: Some(service),
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
    /// Records the service a Negotiate proof was made for.
    pub(super) fn made_from(mut self, made: Option<String>) -> Self {
        self.made = made;
        self
    }

    /// The parent accepted the proof.
    pub(super) fn accepted(self) {
        self.auth.verified.store(true, Ordering::Release);
        tracing::debug!("the parent proxy accepted the credentials");
    }

    /// The parent refused the proof. Every proof gatir can still have here is
    /// password-derived (NTLM, configured or of the system: see the module
    /// doc), so this always keeps gatir away from the parent for a while.
    pub(super) fn refused(self) -> Failure {
        match &self.auth.authenticator {
            Authenticator::Ntlm(ntlm) => {
                let user = ntlm.user().to_owned();
                self.auth.hold_off(&user);
                Failure::CredentialsRejected { user }
            }
            Authenticator::Negotiate(_) => {
                let service = self.made.clone().unwrap_or_default();
                self.auth.hold_off("the logged-on user");
                Failure::SessionRejected { service }
            }
        }
    }

    /// The origin server at `host` refused the proof: also a failed logon of
    /// the same account, so it is held off the same way a parent's refusal
    /// would be. Only ever called for an NTLM proof: [`ParentAuth::ntlm_for_origin`]
    /// is what could have made one at all.
    pub(super) fn refused_by_origin(self, host: &str) -> Failure {
        let Authenticator::Ntlm(ntlm) = &self.auth.authenticator else {
            unreachable!("origin auth needs the configured NTLM identity")
        };
        let user = ntlm.user().to_owned();
        self.auth.hold_off(&user);
        Failure::OriginCredentialsRejected {
            user,
            host: host.to_owned(),
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
