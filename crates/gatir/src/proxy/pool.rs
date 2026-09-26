//! Idle HTTP/1 connections to origin servers and parent proxies, kept for reuse.
//!
//! A connection goes back into the pool only once the response it carried has
//! been relayed to the client in full; until then it is busy. Nothing here
//! decides *whether* a connection may be reused: hyper closes a connection the
//! peer ended or announced it would close, and [`Pool::take`] skips those.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use tokio::time::timeout;

use super::body::Body;
use super::upstream::Hop;

/// How long an idle connection may wait to be reused. Servers commonly close
/// idle connections after a few seconds to a minute; older ones would be
/// discarded (or replaced after a failed first use) anyway.
const IDLE_TTL: Duration = Duration::from_secs(30);
/// Idle connections kept per destination.
const MAX_IDLE_PER_KEY: usize = 8;
/// Idle connections kept in total, across destinations.
const MAX_IDLE_TOTAL: usize = 128;
/// How long to wait for a pooled connection to report it is ready.
const READY_WAIT: Duration = Duration::from_millis(50);

/// What a pooled connection leads to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum PoolKey {
    /// A parent proxy, as `host:port`.
    Parent(String),
    /// An origin server, as `host:port`.
    Origin(String),
}

struct Idle {
    sender: SendRequest<Body>,
    since: Instant,
}

#[derive(Default)]
pub(super) struct Pool {
    idle: Mutex<HashMap<PoolKey, Vec<Idle>>>,
    /// Which generation of the settings the connections belong to. A reload
    /// starts a new one: what was opened under an earlier one may have
    /// authenticated as someone else, or lead somewhere else.
    epoch: AtomicU64,
}

impl Pool {
    /// The generation a connection opened now belongs to.
    pub(super) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Forgets the idle connections, and starts a generation that the ones in
    /// use are not part of: they are closed when their response is done.
    pub(super) fn clear(&self) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        idle.clear();
    }

    /// Takes the most recently used idle connection for `key` that is still
    /// usable, if any.
    pub(super) async fn take(&self, key: &PoolKey) -> Option<SendRequest<Body>> {
        loop {
            let candidate = {
                let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
                let list = idle.get_mut(key)?;
                let candidate = list.pop();
                if list.is_empty() {
                    idle.remove(key);
                }
                candidate?
            };
            if candidate.since.elapsed() >= IDLE_TTL || candidate.sender.is_closed() {
                continue;
            }
            let mut sender = candidate.sender;
            if matches!(timeout(READY_WAIT, sender.ready()).await, Ok(Ok(()))) {
                return Some(sender);
            }
        }
    }

    fn put(&self, key: PoolKey, sender: SendRequest<Body>, epoch: u64) {
        if sender.is_closed() {
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if epoch != self.epoch() {
            return;
        }
        idle.values_mut().for_each(|list| {
            list.retain(|entry| entry.since.elapsed() < IDLE_TTL && !entry.sender.is_closed());
        });
        idle.retain(|_, list| !list.is_empty());

        if idle.values().map(Vec::len).sum::<usize>() >= MAX_IDLE_TOTAL {
            return;
        }
        let list = idle.entry(key).or_default();
        if list.len() >= MAX_IDLE_PER_KEY {
            list.remove(0);
        }
        list.push(Idle {
            sender,
            since: Instant::now(),
        });
    }
}

/// A connection checked out of the pool, or freshly opened, for one exchange.
pub(super) struct Lease {
    pub sender: SendRequest<Body>,
    pub key: PoolKey,
    /// The way it reaches the destination.
    pub hop: Hop,
    /// True if it came from the pool, so it may have gone stale unnoticed.
    pub reused: bool,
    /// True for a new connection to a parent that wants authentication: the
    /// exchange must run on it before it carries the request. Pooled
    /// connections have been through it already.
    pub needs_auth: bool,
    /// The generation of the settings it was opened under, for the pool.
    pub epoch: u64,
}

impl Lease {
    /// Wraps the response body so that the connection returns to `pool` once
    /// the whole body has been relayed.
    pub(super) fn attach(self, pool: &Arc<Pool>, body: Incoming) -> Body {
        let release = Release {
            pool: pool.clone(),
            key: self.key,
            sender: self.sender,
            epoch: self.epoch,
        };
        if body.is_end_stream() {
            release.give_back();
            return body.boxed_unsync();
        }
        PooledBody {
            inner: body,
            release: Some(release),
        }
        .boxed_unsync()
    }
}

struct Release {
    pool: Arc<Pool>,
    key: PoolKey,
    sender: SendRequest<Body>,
    epoch: u64,
}

impl Release {
    fn give_back(self) {
        self.pool.put(self.key, self.sender, self.epoch);
    }
}

/// A response body that hands its connection back to the pool when it ends.
/// If it is dropped or fails first, the connection is simply closed.
struct PooledBody {
    inner: Incoming,
    release: Option<Release>,
}

impl HttpBody for PooledBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        match &poll {
            Poll::Ready(None) => self.give_back(),
            // A body with a known length is complete after its last frame, and
            // hyper may never poll it again.
            Poll::Ready(Some(Ok(_))) if self.inner.is_end_stream() => self.give_back(),
            Poll::Ready(Some(Err(_))) => self.release = None,
            _ => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl PooledBody {
    fn give_back(&mut self) {
        if let Some(release) = self.release.take() {
            release.give_back();
        }
    }
}
