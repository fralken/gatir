//! Choosing where a request goes, and connecting there: straight to the origin
//! server, or through a parent proxy.
//!
//! A request has an ordered list of [`Hop`]s to try. With a fixed list of
//! parents that is the list of parents, starting from the one that worked last;
//! either way, the first that answers is used.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hyper::client::conn::http1::SendRequest;
use tokio::net::TcpStream;

use super::body::Body;
use super::failure::{ConnectError, Failure, ParentAttempt, connect_failure, try_connect};
use super::parent::ParentAuth;
use super::pool::{Pool, PoolKey};
use crate::config::HostPort;
use crate::noproxy::NoProxy;
use crate::pac::{PacSource, Route};

/// How long a parent that could not be reached is left for last.
const BAD_FOR: Duration = Duration::from_secs(60);

/// One way to reach a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Hop {
    /// Connect to the destination itself.
    Direct,
    /// Send the request to a parent proxy.
    Parent(HostPort),
}

impl Hop {
    pub(super) fn is_parent(&self) -> bool {
        matches!(self, Self::Parent(_))
    }

    /// What connections made through this hop are kept under: `origin` is the
    /// destination's `host:port`, which only a direct connection is tied to.
    pub(super) fn pool_key(&self, origin: &str) -> PoolKey {
        match self {
            Self::Direct => PoolKey::Origin(origin.to_owned()),
            Self::Parent(parent) => PoolKey::Parent(parent.to_string()),
        }
    }

    /// Who a message about this hop should blame.
    pub(super) fn who(&self) -> &'static str {
        match self {
            Self::Direct => "the upstream server",
            Self::Parent(_) => "the parent proxy",
        }
    }
}

/// What opening a connection came to.
pub(super) enum Opened {
    /// The pool had a connection for this hop.
    Reused(Hop, SendRequest<Body>),
    /// A new TCP connection.
    New(Hop, TcpStream),
}

pub(super) struct Upstreams {
    parents: Vec<HostPort>,
    /// Index of the parent used most recently with success. Requests start
    /// there, so a healthy parent is kept ("sticky") until it fails.
    current: AtomicUsize,
    no_proxy: NoProxy,
    /// A PAC script that says where each request goes, in place of `parents`.
    pac: Option<Arc<PacSource>>,
    /// Parents that could not be reached, and when.
    unreachable: Mutex<HashMap<String, Instant>>,
}

impl Upstreams {
    pub(super) fn new(
        parents: Vec<HostPort>,
        no_proxy: NoProxy,
        pac: Option<Arc<PacSource>>,
    ) -> Self {
        Self {
            parents,
            current: AtomicUsize::new(0),
            no_proxy,
            pac,
            unreachable: Mutex::new(HashMap::new()),
        }
    }

    /// Where a request for `url`, whose host is `host`, may go, in order.
    ///
    /// Destinations listed in `no_proxy` are always direct. Otherwise a PAC
    /// script decides, if there is one; else it is the configured parents, or
    /// straight to the destination if there are none.
    pub(super) async fn hops(&self, url: &str, host: &str) -> Result<Vec<Hop>, Failure> {
        let host = host.to_ascii_lowercase();
        if self.no_proxy.matches(&host) {
            return Ok(vec![Hop::Direct]);
        }
        if let Some(pac) = &self.pac {
            return hops_from_script(pac, url, &host).await;
        }
        let count = self.parents.len();
        if count == 0 {
            return Ok(vec![Hop::Direct]);
        }
        let start = self.current.load(Ordering::Relaxed) % count;
        Ok((0..count)
            .map(|offset| Hop::Parent(self.parents[(start + offset) % count].clone()))
            .collect())
    }

    fn unreachable(&self) -> std::sync::MutexGuard<'_, HashMap<String, Instant>> {
        self.unreachable
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The hops with the parents that could not be reached lately moved to the
    /// end, so a dead proxy does not cost a connection timeout on every request.
    /// If all of them failed lately, the order is left as it is.
    fn order(&self, hops: Vec<Hop>) -> Vec<Hop> {
        let mut unreachable = self.unreachable();
        unreachable.retain(|_, since| since.elapsed() < BAD_FOR);
        let (mut good, bad): (Vec<Hop>, Vec<Hop>) = hops.into_iter().partition(|hop| match hop {
            Hop::Direct => true,
            Hop::Parent(parent) => !unreachable.contains_key(&parent.to_string()),
        });
        good.extend(bad);
        good
    }

    fn worked(&self, hop: &Hop) {
        let Hop::Parent(parent) = hop else { return };
        self.unreachable().remove(&parent.to_string());
        if let Some(index) = self.parents.iter().position(|known| known == parent) {
            self.current.store(index, Ordering::Relaxed);
        }
    }

    fn failed(&self, hop: &Hop) {
        if let Hop::Parent(parent) = hop {
            self.unreachable()
                .insert(parent.to_string(), Instant::now());
        }
    }

    /// Opens a TCP connection to the destination `origin` (`host:port`) through
    /// `hop`.
    pub(super) async fn connect_hop(
        &self,
        hop: &Hop,
        origin: &str,
        limit: Duration,
    ) -> Result<TcpStream, Failure> {
        let result = match hop {
            Hop::Direct => try_connect(origin, limit).await,
            Hop::Parent(parent) => try_connect(&parent.to_string(), limit).await,
        };
        match result {
            Ok(stream) => {
                self.worked(hop);
                Ok(stream)
            }
            Err(error) => {
                tracing::warn!(hop = %hop_name(hop), %error, "cannot connect");
                self.failed(hop);
                Err(hop_failure(hop, origin, error))
            }
        }
    }

    /// Like [`Upstreams::open`], for a connection that is never reused.
    pub(super) async fn connect(
        &self,
        hops: Vec<Hop>,
        origin: &str,
        limit: Duration,
        auth: Option<&ParentAuth>,
    ) -> Result<(Hop, TcpStream), Failure> {
        match self.open(hops, origin, limit, auth, None).await? {
            Opened::New(hop, stream) => Ok((hop, stream)),
            Opened::Reused(..) => Err(Failure::Parent("a connection was reused with no pool")),
        }
    }

    /// Tries the hops in order and returns the first that answers.
    ///
    /// `pool` is asked for each hop before a new connection to it is opened.
    /// `auth` is what the parents need: while it is holding off after
    /// credentials were refused, a parent is not tried (a pooled connection is
    /// another matter).
    pub(super) async fn open(
        &self,
        hops: Vec<Hop>,
        origin: &str,
        limit: Duration,
        auth: Option<&ParentAuth>,
        pool: Option<&Pool>,
    ) -> Result<Opened, Failure> {
        let mut parents_tried = Vec::new();
        let mut direct_failure = None;
        let mut held_off = None;
        let first = hops.first().cloned();

        for hop in self.order(hops) {
            if let Some(pool) = pool
                && let Some(sender) = pool.take(&hop.pool_key(origin)).await
            {
                return Ok(Opened::Reused(hop, sender));
            }
            if let (Hop::Parent(_), Some(auth)) = (&hop, auth)
                && let Err(failure) = auth.check()
            {
                held_off = Some(failure);
                continue;
            }
            match self.connect_hop(&hop, origin, limit).await {
                Ok(stream) => {
                    if let (Some(first), Hop::Parent(parent)) = (&first, &hop)
                        && *first != hop
                    {
                        tracing::info!(parent = %parent, "using another parent proxy");
                    }
                    return Ok(Opened::New(hop, stream));
                }
                Err(failure) => match hop {
                    Hop::Parent(_) => {
                        if let Failure::ParentsUnavailable(mut attempts) = failure {
                            parents_tried.append(&mut attempts);
                        }
                    }
                    Hop::Direct => direct_failure = Some(failure),
                },
            }
        }
        // Blame what was tried last and matters most: the destination itself if
        // it was tried, else the parents.
        if let Some(failure) = direct_failure {
            return Err(failure);
        }
        if !parents_tried.is_empty() {
            return Err(Failure::ParentsUnavailable(parents_tried));
        }
        Err(held_off.unwrap_or(Failure::Parent("there is nowhere to send the request")))
    }
}

/// The hops a PAC script chose, skipping the kinds gatir cannot use.
async fn hops_from_script(source: &PacSource, url: &str, host: &str) -> Result<Vec<Hop>, Failure> {
    let pac = source.current().map_err(Failure::Pac)?;
    let routes = pac.find(url, host).await.map_err(Failure::Pac)?;
    let mut hops = Vec::new();
    let mut skipped = Vec::new();
    for route in routes {
        match route {
            Route::Direct => hops.push(Hop::Direct),
            Route::Proxy(proxy) => hops.push(Hop::Parent(HostPort {
                host: proxy.host,
                port: proxy.port,
            })),
            other => skipped.push(other.to_string()),
        }
    }
    tracing::debug!(%url, chosen = ?hops, ?skipped, "the PAC script chose");
    if hops.is_empty() {
        return Err(Failure::PacUnsupported(skipped.join("; ")));
    }
    Ok(hops)
}

fn hop_name(hop: &Hop) -> String {
    match hop {
        Hop::Direct => "DIRECT".to_owned(),
        Hop::Parent(parent) => parent.to_string(),
    }
}

/// A failure to connect through `hop`, as something to tell the client.
fn hop_failure(hop: &Hop, origin: &str, error: ConnectError) -> Failure {
    match hop {
        Hop::Direct => connect_failure(origin, error),
        Hop::Parent(parent) => Failure::ParentsUnavailable(vec![ParentAttempt {
            address: parent.to_string(),
            error,
        }]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent(text: &str) -> HostPort {
        text.parse().unwrap()
    }

    fn hop(text: &str) -> Hop {
        Hop::Parent(parent(text))
    }

    #[tokio::test]
    async fn without_parents_everything_is_direct() {
        let upstreams = Upstreams::new(vec![], NoProxy::default(), None);
        assert_eq!(
            upstreams
                .hops("http://example.com/", "example.com")
                .await
                .unwrap(),
            [Hop::Direct]
        );
    }

    #[tokio::test]
    async fn with_parents_only_no_proxy_destinations_are_direct() {
        let no_proxy = NoProxy::new(["localhost", "*.corp.example.com", "10.0.0.0/8"]).unwrap();
        let upstreams = Upstreams::new(vec![parent("proxy.example.com:8080")], no_proxy, None);
        let hops = |host: &'static str| {
            let upstreams = &upstreams;
            async move { upstreams.hops("http://x/", host).await.unwrap() }
        };

        assert_eq!(hops("example.com").await, [hop("proxy.example.com:8080")]);
        assert_eq!(hops("localhost").await, [Hop::Direct]);
        assert_eq!(hops("LOCALHOST").await, [Hop::Direct]);
        assert_eq!(hops("app.corp.example.com").await, [Hop::Direct]);
        assert_eq!(hops("10.1.2.3").await, [Hop::Direct]);
        assert_eq!(hops("11.1.2.3").await, [hop("proxy.example.com:8080")]);
        assert_eq!(hops("[::1]").await, [hop("proxy.example.com:8080")]);
    }

    #[tokio::test]
    async fn the_parent_that_worked_last_comes_first() {
        let upstreams = Upstreams::new(
            vec![
                parent("a.example.com:1"),
                parent("b.example.com:2"),
                parent("c.example.com:3"),
            ],
            NoProxy::default(),
            None,
        );
        assert_eq!(
            upstreams.hops("http://x/", "x").await.unwrap(),
            [
                hop("a.example.com:1"),
                hop("b.example.com:2"),
                hop("c.example.com:3")
            ]
        );
        upstreams.worked(&hop("b.example.com:2"));
        assert_eq!(
            upstreams.hops("http://x/", "x").await.unwrap(),
            [
                hop("b.example.com:2"),
                hop("c.example.com:3"),
                hop("a.example.com:1")
            ]
        );
    }

    #[test]
    fn a_parent_that_could_not_be_reached_goes_last_for_a_while() {
        let upstreams = Upstreams::new(vec![], NoProxy::default(), None);
        let hops = vec![
            hop("dead.example.com:1"),
            Hop::Direct,
            hop("live.example.com:2"),
        ];

        upstreams.failed(&hop("dead.example.com:1"));
        assert_eq!(
            upstreams.order(hops.clone()),
            [
                Hop::Direct,
                hop("live.example.com:2"),
                hop("dead.example.com:1")
            ]
        );

        // Once it works again it takes its place back.
        upstreams.worked(&hop("dead.example.com:1"));
        assert_eq!(upstreams.order(hops.clone()), hops);
    }

    #[test]
    fn when_every_parent_failed_the_order_is_kept() {
        let upstreams = Upstreams::new(vec![], NoProxy::default(), None);
        let hops = vec![hop("a.example.com:1"), hop("b.example.com:2")];
        upstreams.failed(&hops[0]);
        upstreams.failed(&hops[1]);
        assert_eq!(upstreams.order(hops.clone()), hops);
    }

    #[test]
    fn a_direct_hop_is_tied_to_its_destination_and_a_parent_is_not() {
        assert_eq!(
            Hop::Direct.pool_key("origin.example.com:80"),
            PoolKey::Origin("origin.example.com:80".to_owned())
        );
        assert_eq!(
            hop("proxy.example.com:8080").pool_key("origin.example.com:80"),
            PoolKey::Parent("proxy.example.com:8080".to_owned())
        );
    }
}
