//! Name resolution for the PAC helpers.
//!
//! A PAC script may call `dnsResolve` several times per request, and a lookup
//! that hangs cannot be interrupted from inside the script engine. So lookups
//! run on their own threads, and the script waits for them for a limited time
//! only. A name is looked up once at a time: whoever asks for it while its
//! lookup runs waits for that lookup, and once someone has waited for it in
//! vain, those who ask next do not wait at all. Answers are cached, so a name
//! that was answered is not waited for again either.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// At most this many lookups are in progress at once; more are refused.
const MAX_IN_FLIGHT: usize = 16;
/// Most names remembered. When the cache is full it is emptied.
const MAX_CACHED: usize = 4096;
/// How long a failed lookup is remembered, at most.
const NEGATIVE_TTL: Duration = Duration::from_secs(10);

/// What a PAC script asks of the network: the addresses of names, and of this
/// machine.
pub trait Resolver: Send + Sync + fmt::Debug {
    /// The addresses of `host`, IPv4 ones first. Empty if the name does not
    /// resolve, or the lookup takes too long.
    fn resolve(&self, host: &str) -> Vec<IpAddr>;

    /// The addresses this machine would use to reach the network, IPv4 first.
    /// Empty if it has no route at all.
    fn local_addresses(&self) -> Vec<IpAddr> {
        system_local_addresses()
    }
}

/// The address a socket would leave from. Connecting a UDP socket sends
/// nothing: it only makes the system pick the outgoing interface.
fn local_address(remote: &str, bind: &str) -> Option<IpAddr> {
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(remote).ok()?;
    socket.local_addr().ok().map(|address| address.ip())
}

/// The addresses of this machine on its way out. The remote addresses are
/// reserved for documentation, so nothing is ever sent to them.
pub fn system_local_addresses() -> Vec<IpAddr> {
    [
        local_address("192.0.2.1:9", "0.0.0.0:0"),
        local_address("[2001:db8::1]:9", "[::]:0"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The address `myIpAddress()` gives when there is no route.
pub(super) const NO_ROUTE: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

type Lookup = dyn Fn(&str) -> Vec<IpAddr> + Send + Sync;

struct Cached {
    addresses: Vec<IpAddr>,
    until: Instant,
}

/// A lookup under way, shared by everyone who asks for its name meanwhile.
#[derive(Default)]
struct Pending {
    state: Mutex<PendingState>,
    done: Condvar,
}

#[derive(Default)]
struct PendingState {
    /// The answer, once the lookup is done.
    addresses: Option<Vec<IpAddr>>,
    /// Someone waited for the whole time limit without an answer.
    given_up: bool,
}

impl Pending {
    fn lock(&self) -> std::sync::MutexGuard<'_, PendingState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits at most `timeout` for the answer. Does not wait at all if someone
    /// already waited in vain: the lookup has shown that it is slow.
    fn wait(&self, timeout: Duration) -> Option<Vec<IpAddr>> {
        let state = self.lock();
        if state.addresses.is_none() && state.given_up {
            return None;
        }
        let (mut state, _) = self
            .done
            .wait_timeout_while(state, timeout, |state| state.addresses.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        if state.addresses.is_none() {
            state.given_up = true;
        }
        state.addresses.clone()
    }

    fn finish(&self, addresses: Vec<IpAddr>) {
        self.lock().addresses = Some(addresses);
        self.done.notify_all();
    }
}

struct Inner {
    lookup: Box<Lookup>,
    ttl: Duration,
    cache: Mutex<HashMap<String, Cached>>,
    /// The lookups under way, by name.
    pending: Mutex<HashMap<String, Arc<Pending>>>,
    in_flight: AtomicUsize,
}

impl Inner {
    fn cached(&self, name: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .get(name)
            .filter(|entry| entry.until > Instant::now())
            .map(|entry| entry.addresses.clone())
    }

    fn store(&self, name: String, addresses: Vec<IpAddr>) {
        let ttl = if addresses.is_empty() {
            self.ttl.min(NEGATIVE_TTL)
        } else {
            self.ttl
        };
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= MAX_CACHED {
            cache.clear();
        }
        cache.insert(
            name,
            Cached {
                addresses,
                until: Instant::now() + ttl,
            },
        );
    }
}

/// The resolver of the system, with a time limit and a cache.
#[derive(Clone)]
pub struct SystemResolver {
    inner: Arc<Inner>,
    timeout: Duration,
}

impl fmt::Debug for SystemResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemResolver")
            .field("timeout", &self.timeout)
            .field("ttl", &self.inner.ttl)
            .finish_non_exhaustive()
    }
}

impl SystemResolver {
    /// Waits at most `timeout` for a lookup, and remembers answers for `ttl`.
    pub fn new(timeout: Duration, ttl: Duration) -> Self {
        Self::with_lookup(timeout, ttl, system_lookup)
    }

    /// Like [`SystemResolver::new`], with another way to look names up.
    pub fn with_lookup(
        timeout: Duration,
        ttl: Duration,
        lookup: impl Fn(&str) -> Vec<IpAddr> + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                lookup: Box::new(lookup),
                ttl,
                cache: Mutex::new(HashMap::new()),
                pending: Mutex::new(HashMap::new()),
                in_flight: AtomicUsize::new(0),
            }),
            timeout,
        }
    }
}

fn system_lookup(host: &str) -> Vec<IpAddr> {
    let mut found: Vec<IpAddr> = Vec::new();
    if let Ok(addresses) = (host, 0).to_socket_addrs() {
        for address in addresses {
            if !found.contains(&address.ip()) {
                found.push(address.ip());
            }
        }
    }
    found
}

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> Vec<IpAddr> {
        let name = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let literal = name.trim_start_matches('[').trim_end_matches(']');
        if let Ok(address) = literal.parse::<IpAddr>() {
            return vec![address];
        }
        if name.is_empty() {
            return Vec::new();
        }
        if let Some(addresses) = self.inner.cached(&name) {
            return addresses;
        }
        let Some(pending) = self.pending(&name) else {
            return Vec::new();
        };
        pending.wait(self.timeout).unwrap_or_else(|| {
            tracing::debug!(%name, "name lookup timed out");
            Vec::new()
        })
    }
}

impl SystemResolver {
    /// The lookup of `name` under way, started now if there is none. `None`
    /// if it cannot be started.
    fn pending(&self, name: &str) -> Option<Arc<Pending>> {
        let mut pending = self
            .inner
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(under_way) = pending.get(name) {
            return Some(under_way.clone());
        }
        // The answer may have arrived since the cache was asked.
        if let Some(addresses) = self.inner.cached(name) {
            let done = Arc::new(Pending::default());
            done.finish(addresses);
            return Some(done);
        }
        if self.inner.in_flight.fetch_add(1, Ordering::AcqRel) >= MAX_IN_FLIGHT {
            self.inner.in_flight.fetch_sub(1, Ordering::AcqRel);
            tracing::debug!(%name, "too many name lookups in progress, giving up on this one");
            return None;
        }

        let lookup = Arc::new(Pending::default());
        let inner = self.inner.clone();
        let shared = lookup.clone();
        let lookup_name = name.to_owned();
        let started = std::thread::Builder::new()
            .name("gatir-dns".to_owned())
            .spawn(move || {
                let mut addresses = (inner.lookup)(&lookup_name);
                // IPv4 first: `dnsResolve` returns the first address.
                addresses.sort_by_key(IpAddr::is_ipv6);
                // Cached before the lookup stops being under way, so that a
                // caller always finds one or the other.
                inner.store(lookup_name.clone(), addresses.clone());
                inner
                    .pending
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&lookup_name);
                inner.in_flight.fetch_sub(1, Ordering::AcqRel);
                shared.finish(addresses);
            });
        if started.is_err() {
            self.inner.in_flight.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        pending.insert(name.to_owned(), lookup.clone());
        Some(lookup)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicU32;

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn an_address_needs_no_lookup() {
        let resolver =
            SystemResolver::with_lookup(Duration::from_secs(1), Duration::from_secs(60), |_| {
                panic!("no lookup for an address")
            });
        assert_eq!(resolver.resolve("10.1.2.3"), [v4(10, 1, 2, 3)]);
        assert_eq!(
            resolver.resolve("[::1]"),
            ["::1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            resolver.resolve("2001:db8::1"),
            ["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn answers_are_remembered() {
        let calls = Arc::new(AtomicU32::new(0));
        let counted = calls.clone();
        let resolver = SystemResolver::with_lookup(
            Duration::from_secs(1),
            Duration::from_secs(60),
            move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                vec![v4(1, 2, 3, 4)]
            },
        );
        for _ in 0..3 {
            assert_eq!(resolver.resolve("Host.Example.COM."), [v4(1, 2, 3, 4)]);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ipv4_addresses_come_first() {
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let resolver = SystemResolver::with_lookup(
            Duration::from_secs(1),
            Duration::from_secs(60),
            move |_| vec![v6, v4(1, 2, 3, 4)],
        );
        assert_eq!(resolver.resolve("dual.example.com"), [v4(1, 2, 3, 4), v6]);
    }

    #[test]
    fn a_slow_lookup_is_given_up_on_but_still_helps_the_next_call() {
        let resolver = SystemResolver::with_lookup(
            Duration::from_millis(100),
            Duration::from_secs(60),
            |_| {
                std::thread::sleep(Duration::from_millis(400));
                vec![v4(9, 9, 9, 9)]
            },
        );
        let started = Instant::now();
        assert!(resolver.resolve("slow.example.com").is_empty());
        assert!(
            started.elapsed() < Duration::from_millis(350),
            "{:?}",
            started.elapsed()
        );

        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(resolver.resolve("slow.example.com"), [v4(9, 9, 9, 9)]);
    }

    #[test]
    fn a_name_asked_for_while_it_is_looked_up_waits_for_that_lookup() {
        let calls = Arc::new(AtomicU32::new(0));
        let counted = calls.clone();
        let resolver = SystemResolver::with_lookup(
            Duration::from_secs(2),
            Duration::from_secs(60),
            move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(200));
                vec![v4(5, 5, 5, 5)]
            },
        );
        let answers: Vec<Vec<IpAddr>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..5)
                .map(|_| scope.spawn(|| resolver.resolve("shared.example.com")))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(
            answers.iter().all(|a| a == &[v4(5, 5, 5, 5)]),
            "{answers:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn once_a_lookup_was_waited_for_in_vain_the_next_call_does_not_wait() {
        // A script that asks about the same name three times, while the DNS
        // does not answer, waits for it once, not three times.
        let calls = Arc::new(AtomicU32::new(0));
        let counted = calls.clone();
        let resolver = SystemResolver::with_lookup(
            Duration::from_millis(150),
            Duration::from_secs(60),
            move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(800));
                vec![v4(7, 7, 7, 7)]
            },
        );
        let started = Instant::now();
        for _ in 0..3 {
            assert!(resolver.resolve("hanging.example.com").is_empty());
        }
        let waited = started.elapsed();
        assert!(waited < Duration::from_millis(400), "{waited:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // When the lookup does end, its answer is there for the next call.
        std::thread::sleep(Duration::from_millis(900));
        assert_eq!(resolver.resolve("hanging.example.com"), [v4(7, 7, 7, 7)]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_failure_is_remembered_for_a_short_time() {
        let calls = Arc::new(AtomicU32::new(0));
        let counted = calls.clone();
        let resolver = SystemResolver::with_lookup(
            Duration::from_secs(1),
            Duration::from_secs(60),
            move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                Vec::new()
            },
        );
        assert!(resolver.resolve("nothing.example.com").is_empty());
        assert!(resolver.resolve("nothing.example.com").is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn too_many_lookups_at_once_are_refused() {
        let resolver =
            SystemResolver::with_lookup(Duration::from_millis(50), Duration::from_secs(60), |_| {
                std::thread::sleep(Duration::from_millis(600));
                vec![v4(1, 1, 1, 1)]
            });
        let refused = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..MAX_IN_FLIGHT + 4)
                .map(|n| {
                    let resolver = resolver.clone();
                    scope.spawn(move || resolver.resolve(&format!("h{n}.example.com")))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|a| a.is_empty())
                .count()
        });
        // All of them time out here; the point is that none of them panics or hangs.
        assert_eq!(refused, MAX_IN_FLIGHT + 4);
    }

    #[test]
    fn the_system_resolves_localhost() {
        let resolver = SystemResolver::new(Duration::from_secs(5), Duration::from_secs(60));
        let found = resolver.resolve("localhost");
        assert!(found.iter().any(IpAddr::is_loopback), "{found:?}");
    }
}
