//! Proxy auto-configuration: a PAC script decides, for each URL, whether to go
//! direct or through which proxies.
//!
//! The script is JavaScript with a few helper functions defined by the host.
//! It runs in an engine with limits on time, memory and stack; see
//! [`PacLimits`]. What it returns is read into a list of [`Route`]s.

mod engine;
mod helpers;
mod resolver;
mod route;

pub use engine::{Pac, PacEnv, PacError, PacLimits};
pub use resolver::{Resolver, SystemResolver};
pub use route::{Parsed, ProxyAddr, Route, parse};
