//! Logging setup.

use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;

use crate::config::LogLevel;

/// Installs the global subscriber, writing to stderr. `RUST_LOG`, when set,
/// takes precedence over `level`.
///
/// Colors are for a person at a terminal: a log that goes to a file, the
/// journal or a pipe gets none, or every line would carry escape sequences.
pub fn init(level: LogLevel) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));
    let colors = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(colors)
        .init();
}
