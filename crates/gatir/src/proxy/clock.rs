//! The time the proxy reads for what it remembers for a while: a parent that
//! failed (a minute), and a refusal of the credentials (five minutes).

use std::fmt;
use std::time::{Duration, Instant};

/// Where the proxy reads the time. Tests put one in [`Services`] that they move
/// on at will, so that what expires can be tested without waiting for it.
///
/// [`Services`]: super::Services
pub trait Clock: Send + Sync + fmt::Debug {
    fn now(&self) -> Instant;
}

/// The system's time.
#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// How long ago `at` was, by `clock`.
pub(super) fn since(clock: &dyn Clock, at: Instant) -> Duration {
    clock.now().saturating_duration_since(at)
}
