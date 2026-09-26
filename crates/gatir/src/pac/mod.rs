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
pub use resolver::{Resolver, SystemResolver, system_local_addresses};
pub use route::{Parsed, ProxyAddr, Route, parse};

use std::fs;
use std::io;
use std::sync::Arc;

use crate::config::PacConfig;

/// The most a PAC file may weigh.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Reads the PAC file named in the configuration and loads it, so that a file
/// that is missing, too large or wrong is found at start-up, not on the first
/// request.
pub fn load_file(settings: &PacConfig) -> io::Result<Pac> {
    let describe = |what: String| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "cannot use the PAC file {}: {what}",
                settings.file.display()
            ),
        )
    };
    let size = fs::metadata(&settings.file)
        .map_err(|err| describe(err.to_string()))?
        .len();
    if size > MAX_FILE_BYTES {
        return Err(describe(format!(
            "it is {size} bytes, more than the {MAX_FILE_BYTES} allowed"
        )));
    }
    let bytes = fs::read(&settings.file).map_err(|err| describe(err.to_string()))?;
    // Scripts written years ago are not always UTF-8.
    let source = String::from_utf8_lossy(&bytes);

    let resolver = Arc::new(SystemResolver::new(settings.dns_timeout, settings.dns_ttl));
    let limits = PacLimits {
        time: settings.time_limit,
        memory: settings.memory_limit,
        workers: settings.workers,
        ..PacLimits::default()
    };
    Pac::load(&source, limits, PacEnv::system(resolver)).map_err(|err| describe(err.to_string()))
}
