//! The `[timeouts]` table.

use std::time::Duration;

use serde::Deserialize;

use super::ConfigError;

/// Longest accepted timeout, in seconds (one day).
const MAX_TIMEOUT_SECS: u64 = 86_400;

/// How long the proxy waits before giving up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeouts {
    /// Opening a TCP connection to an origin server or parent proxy.
    pub connect: Duration,
    /// A client connection that sends nothing (between requests, or while
    /// sending a request head) is closed after this long.
    pub client_idle: Duration,
    /// How long to wait for the head of a response from an origin server or a
    /// parent proxy, counting from the moment the request has been sent. It
    /// also applies to each step of the NTLM exchange.
    pub response: Duration,
    /// A CONNECT tunnel with no traffic in either direction is closed after
    /// this long.
    pub tunnel_idle: Duration,
    /// On shutdown, how long to wait for active connections and tunnels to
    /// finish before closing them.
    pub shutdown_grace: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            client_idle: Duration::from_secs(60),
            response: Duration::from_secs(120),
            tunnel_idle: Duration::from_secs(600),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawTimeouts {
    connect_secs: Option<u64>,
    client_idle_secs: Option<u64>,
    response_secs: Option<u64>,
    tunnel_idle_secs: Option<u64>,
    shutdown_grace_secs: Option<u64>,
}

impl RawTimeouts {
    pub(super) fn resolve(self) -> Result<Timeouts, ConfigError> {
        let defaults = Timeouts::default();
        Ok(Timeouts {
            connect: timeout("connect_secs", self.connect_secs, defaults.connect)?,
            client_idle: timeout(
                "client_idle_secs",
                self.client_idle_secs,
                defaults.client_idle,
            )?,
            response: timeout("response_secs", self.response_secs, defaults.response)?,
            tunnel_idle: timeout(
                "tunnel_idle_secs",
                self.tunnel_idle_secs,
                defaults.tunnel_idle,
            )?,
            shutdown_grace: timeout(
                "shutdown_grace_secs",
                self.shutdown_grace_secs,
                defaults.shutdown_grace,
            )?,
        })
    }
}

fn timeout(name: &str, secs: Option<u64>, default: Duration) -> Result<Duration, ConfigError> {
    match secs {
        None => Ok(default),
        Some(secs) if (1..=MAX_TIMEOUT_SECS).contains(&secs) => Ok(Duration::from_secs(secs)),
        Some(_) => Err(ConfigError::invalid(format!(
            "timeouts.{name} must be between 1 and {MAX_TIMEOUT_SECS} seconds"
        ))),
    }
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use crate::config::testing::{error_text, load};

    use super::*;

    #[test]
    fn timeouts_have_defaults_and_can_be_overridden() {
        assert_eq!(load("").unwrap().timeouts, Timeouts::default());

        let config = load(
            "[timeouts]\nconnect_secs = 3\nresponse_secs = 45\ntunnel_idle_secs = 90\n\
             shutdown_grace_secs = 2",
        )
        .unwrap();
        assert_eq!(config.timeouts.connect, Duration::from_secs(3));
        assert_eq!(config.timeouts.response, Duration::from_secs(45));
        assert_eq!(config.timeouts.tunnel_idle, Duration::from_secs(90));
        assert_eq!(config.timeouts.shutdown_grace, Duration::from_secs(2));
        assert_eq!(config.timeouts.client_idle, Timeouts::default().client_idle);
    }

    #[test]
    fn rejects_invalid_timeouts() {
        for toml in [
            "[timeouts]\nconnect_secs = 0",
            "[timeouts]\nclient_idle_secs = 86401",
            "[timeouts]\ntunnel_idle_secs = -5",
            "[timeouts]\nshutdown_grace_secs = 0",
            "[timeouts]\nresponse_secs = 0",
            "[timeouts]\nconnect = 5",
        ] {
            assert!(load(toml).is_err(), "should reject {toml:?}");
        }
        assert!(error_text("[timeouts]\nconnect_secs = 0").contains("timeouts.connect_secs"));
    }
}
