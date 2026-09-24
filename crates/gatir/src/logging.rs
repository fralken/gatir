//! Logging setup.

use tracing_subscriber::EnvFilter;

use crate::config::LogLevel;

/// Installs the global subscriber, writing to stderr. `RUST_LOG`, when set,
/// takes precedence over `level`.
pub fn init(level: LogLevel) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
