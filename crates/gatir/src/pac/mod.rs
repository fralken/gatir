//! Proxy auto-configuration: a PAC script decides, for each URL, whether to go
//! direct or through which proxies.
//!
//! The script is JavaScript with a few helper functions defined by the host.
//! It runs in an engine with limits on time, memory and stack; see
//! [`PacLimits`]. What it returns is read into a list of [`Route`]s.
//!
//! The script comes from a file or an address, and [`PacSource`] keeps it up to
//! date: a version that fails to load never replaces one that works.

mod engine;
mod fetch;
mod helpers;
mod resolver;
mod route;
mod source;

pub use engine::{Pac, PacEnv, PacError, PacLimits};
pub use fetch::{FetchError, Fetched, Trust, Validators, fetch};
pub use resolver::{Resolver, SystemResolver, system_local_addresses};
pub use route::{Parsed, ProxyAddr, Route, parse};
pub use source::PacSource;

/// The most a PAC script may weigh.
const MAX_SCRIPT_BYTES: usize = 16 * 1024 * 1024;
