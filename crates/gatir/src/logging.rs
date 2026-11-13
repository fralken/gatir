//! Logging setup.

use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;

use crate::config::LogLevel;

/// Installs the global subscriber, writing to stderr. `RUST_LOG`, when set,
/// takes precedence over `level`, and is the way to see a dependency's own
/// logging (`level` only ever turns gatir's own up or down).
///
/// Colors are for a person at a terminal: a log that goes to a file, the
/// journal or a pipe gets none, or every line would carry escape sequences.
pub fn init(level: LogLevel) {
    let fallback = || EnvFilter::new(format!("gatir={}", level.as_str()));
    let (filter, refused) = match EnvFilter::try_from_default_env() {
        Ok(filter) => (filter, None),
        // Set, but not a filter: said once logging works, or a typo in it
        // would go unnoticed.
        Err(err) if std::env::var(EnvFilter::DEFAULT_ENV).is_ok_and(|v| !v.trim().is_empty()) => {
            (fallback(), Some(err))
        }
        // Not set, or empty.
        Err(_) => (fallback(), None),
    };
    let colors = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(colors)
        .init();
    if let Some(err) = refused {
        tracing::warn!(%err, "RUST_LOG is not a valid filter: using the log level instead");
    }
}
