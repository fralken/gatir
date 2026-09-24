//! Choosing where a request goes: straight to the origin server, or through a
//! parent proxy.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;

use super::failure::{Failure, ParentAttempt, try_connect};
use crate::config::ParentAddr;
use crate::noproxy::NoProxy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Route {
    /// Connect to the destination itself.
    Direct,
    /// Send the request to a parent proxy.
    Parent,
}

pub(super) struct Upstreams {
    parents: Vec<ParentAddr>,
    /// Index of the parent used most recently with success. Requests start
    /// there, so a healthy parent is kept ("sticky") until it fails.
    current: AtomicUsize,
    no_proxy: NoProxy,
}

impl Upstreams {
    pub(super) fn new(parents: Vec<ParentAddr>, no_proxy: NoProxy) -> Self {
        Self {
            parents,
            current: AtomicUsize::new(0),
            no_proxy,
        }
    }

    /// Without parents everything is direct; with parents, only the
    /// destinations listed in `no_proxy` are.
    pub(super) fn route(&self, host: &str) -> Route {
        if self.parents.is_empty() || self.no_proxy.matches(host) {
            Route::Direct
        } else {
            Route::Parent
        }
    }

    /// Index of the parent that requests currently start with.
    pub(super) fn current_parent(&self) -> usize {
        self.current.load(Ordering::Relaxed) % self.parents.len().max(1)
    }

    /// Connects to a parent proxy, trying the others in order when it is
    /// unreachable. The parent that answers becomes the current one; its index
    /// is returned with the connection.
    pub(super) async fn connect_parent(
        &self,
        limit: Duration,
    ) -> Result<(usize, TcpStream), Failure> {
        let count = self.parents.len();
        let start = self.current.load(Ordering::Relaxed) % count;
        let mut attempts = Vec::new();

        for offset in 0..count {
            let index = (start + offset) % count;
            let address = self.parents[index].to_string();
            match try_connect(&address, limit).await {
                Ok(stream) => {
                    if offset > 0 {
                        tracing::info!(parent = %address, "switched to another parent proxy");
                    }
                    self.current.store(index, Ordering::Relaxed);
                    return Ok((index, stream));
                }
                Err(error) => {
                    tracing::warn!(parent = %address, %error, "cannot connect to the parent proxy");
                    attempts.push(ParentAttempt { address, error });
                }
            }
        }
        Err(Failure::ParentsUnavailable(attempts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent(text: &str) -> ParentAddr {
        text.parse().unwrap()
    }

    #[test]
    fn without_parents_everything_is_direct() {
        let upstreams = Upstreams::new(vec![], NoProxy::default());
        assert_eq!(upstreams.route("example.com"), Route::Direct);
    }

    #[test]
    fn with_parents_only_no_proxy_destinations_are_direct() {
        let no_proxy = NoProxy::new(["localhost", "*.corp.example.com", "10.0.0.0/8"]).unwrap();
        let upstreams = Upstreams::new(vec![parent("proxy.example.com:8080")], no_proxy);

        assert_eq!(upstreams.route("example.com"), Route::Parent);
        assert_eq!(upstreams.route("localhost"), Route::Direct);
        assert_eq!(upstreams.route("app.corp.example.com"), Route::Direct);
        assert_eq!(upstreams.route("10.1.2.3"), Route::Direct);
        assert_eq!(upstreams.route("11.1.2.3"), Route::Parent);
        assert_eq!(upstreams.route("[::1]"), Route::Parent);
    }
}
