//! What the tests of the configuration modules share.

use super::{Config, ConfigError, Overrides};

/// Reads `toml` as a configuration file, with nothing from the command line.
pub(super) fn load(toml: &str) -> Result<Config, ConfigError> {
    Config::from_toml_str(toml, Overrides::default())
}

/// The message of the error that reading `toml` gives.
pub(super) fn error_text(toml: &str) -> String {
    load(toml).unwrap_err().to_string()
}
