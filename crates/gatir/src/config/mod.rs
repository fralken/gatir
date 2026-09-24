//! Configuration: TOML file, overridden by command-line options.
//!
//! Precedence, highest first: command line, config file, built-in defaults.
//! A command-line value replaces the file value; lists are not merged.

mod addr;
mod credentials;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use secrecy::SecretString;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::acl::{Acl, Action, Rule};
use crate::noproxy::NoProxy;

pub use addr::{ParentAddr, ParentAddrError};
use credentials::RawCredentials;
pub use credentials::{AuthMethod, Credentials, NT_HASH_LEN, Secret};

const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3128);

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config at {location}: {message}")]
    Parse { location: String, message: String },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl ConfigError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

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
    /// A CONNECT tunnel with no traffic in either direction is closed after
    /// this long.
    pub tunnel_idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            client_idle: Duration::from_secs(60),
            tunnel_idle: Duration::from_secs(600),
        }
    }
}

/// Fully resolved and validated configuration.
#[derive(Debug)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
    /// Parent proxies in order of preference. Empty means direct connections.
    pub parents: Vec<ParentAddr>,
    pub credentials: Option<Credentials>,
    /// Which client addresses may use the proxy.
    pub access: Acl,
    /// Destinations contacted directly instead of through a parent proxy.
    pub no_proxy: NoProxy,
    pub timeouts: Timeouts,
    pub log_level: LogLevel,
}

/// Values that take precedence over the config file.
#[derive(Debug, Default)]
pub struct Overrides {
    pub listen: Vec<SocketAddr>,
    pub parents: Vec<ParentAddr>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub method: Option<AuthMethod>,
    /// A password supplied interactively. Replaces any password or NT hash
    /// from the config file.
    pub password: Option<SecretString>,
    pub log_level: Option<LogLevel>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: Option<Vec<SocketAddr>>,
    parents: Option<Vec<ParentAddr>>,
    credentials: Option<RawCredentials>,
    access: Option<RawAccess>,
    no_proxy: Option<Vec<String>>,
    timeouts: Option<RawTimeouts>,
    log: Option<RawLog>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTimeouts {
    connect_secs: Option<u64>,
    client_idle_secs: Option<u64>,
    tunnel_idle_secs: Option<u64>,
}

impl RawTimeouts {
    fn resolve(self) -> Result<Timeouts, ConfigError> {
        let defaults = Timeouts::default();
        Ok(Timeouts {
            connect: timeout("connect_secs", self.connect_secs, defaults.connect)?,
            client_idle: timeout(
                "client_idle_secs",
                self.client_idle_secs,
                defaults.client_idle,
            )?,
            tunnel_idle: timeout(
                "tunnel_idle_secs",
                self.tunnel_idle_secs,
                defaults.tunnel_idle,
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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccess {
    default: Option<Action>,
    rules: Option<Vec<Rule>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLog {
    level: Option<LogLevel>,
}

impl Config {
    /// Loads the configuration from `path` (if any) and applies `overrides`.
    pub fn load(path: Option<&Path>, overrides: Overrides) -> Result<Self, ConfigError> {
        let raw = match path {
            Some(path) => {
                // The file may contain a password: wipe our copy once parsed.
                let source = Zeroizing::new(fs::read_to_string(path).map_err(|source| {
                    ConfigError::Read {
                        path: path.to_owned(),
                        source,
                    }
                })?);
                RawConfig::parse(&source, &path.display().to_string())?
            }
            None => RawConfig::default(),
        };
        raw.resolve(overrides)
    }

    /// Like [`Config::load`], reading the TOML from a string.
    pub fn from_toml_str(source: &str, overrides: Overrides) -> Result<Self, ConfigError> {
        RawConfig::parse(source, "<string>")?.resolve(overrides)
    }

    /// A multi-line description that never includes secret values.
    pub fn summary(&self) -> String {
        let listen = join(self.listen.iter());
        let parents = if self.parents.is_empty() {
            "none (direct connections)".to_owned()
        } else {
            join(self.parents.iter())
        };
        let credentials = match &self.credentials {
            None => "none".to_owned(),
            Some(c) => {
                let identity = if c.domain.is_empty() {
                    c.username.clone()
                } else {
                    format!("{}@{}", c.username, c.domain)
                };
                match &c.secret {
                    Some(secret) => format!(
                        "{identity}, method {}, secret: {} (hidden)",
                        c.method.as_str(),
                        secret.kind()
                    ),
                    None => format!("logged-in identity, method {}", c.method.as_str()),
                }
            }
        };
        let access = if self.access.rules().is_empty() {
            format!(
                "default {}, no rules",
                self.access.default_action().as_str()
            )
        } else {
            let rules = join(
                self.access
                    .rules()
                    .iter()
                    .map(|rule| format!("{} {}", rule.action.as_str(), rule.source)),
            );
            format!(
                "default {}; first match wins: {rules}",
                self.access.default_action().as_str()
            )
        };
        let no_proxy = if self.no_proxy.entries().is_empty() {
            "none".to_owned()
        } else {
            join(self.no_proxy.entries().iter())
        };
        let timeouts = format!(
            "connect {}s, client idle {}s, tunnel idle {}s",
            self.timeouts.connect.as_secs(),
            self.timeouts.client_idle.as_secs(),
            self.timeouts.tunnel_idle.as_secs()
        );
        format!(
            "listen:      {listen}\nparents:     {parents}\ncredentials: {credentials}\n\
             access:      {access}\nno_proxy:    {no_proxy}\ntimeouts:    {timeouts}\n\
             log level:   {}",
            self.log_level.as_str()
        )
    }
}

fn join<T: std::fmt::Display>(items: impl Iterator<Item = T>) -> String {
    items.map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
}

impl RawConfig {
    fn parse(source: &str, origin: &str) -> Result<Self, ConfigError> {
        toml::from_str(source).map_err(|err| {
            // Deliberately not `err.to_string()`: it quotes the offending source
            // line, which may contain a password.
            let location = match err.span() {
                Some(span) => {
                    let (line, column) = line_column(source, span.start);
                    format!("{origin}:{line}:{column}")
                }
                None => origin.to_owned(),
            };
            ConfigError::Parse {
                location,
                message: err.message().to_owned(),
            }
        })
    }

    fn resolve(self, overrides: Overrides) -> Result<Config, ConfigError> {
        let listen = if overrides.listen.is_empty() {
            self.listen.unwrap_or_else(|| vec![DEFAULT_LISTEN])
        } else {
            overrides.listen
        };
        if listen.is_empty() {
            return Err(ConfigError::invalid(
                "listen must contain at least one address",
            ));
        }
        for (i, addr) in listen.iter().enumerate() {
            if listen[..i].contains(addr) {
                return Err(ConfigError::invalid(format!(
                    "listen address {addr} is repeated"
                )));
            }
        }

        let parents = if overrides.parents.is_empty() {
            self.parents.unwrap_or_default()
        } else {
            overrides.parents
        };

        let mut credentials = self.credentials;
        if overrides.username.is_some()
            || overrides.domain.is_some()
            || overrides.method.is_some()
            || overrides.password.is_some()
        {
            let raw = credentials.get_or_insert_with(RawCredentials::default);
            if let Some(username) = overrides.username {
                raw.username = Some(username);
            }
            if let Some(domain) = overrides.domain {
                raw.domain = Some(domain);
            }
            if let Some(method) = overrides.method {
                raw.method = Some(method);
            }
            if let Some(password) = overrides.password {
                raw.password = Some(password);
                raw.nt_hash = None;
            }
        }
        let credentials = credentials.map(RawCredentials::validate).transpose()?;

        let access = self
            .access
            .map(|raw| {
                Acl::new(
                    raw.rules.unwrap_or_default(),
                    raw.default.unwrap_or_default(),
                )
            })
            .unwrap_or_default();

        let no_proxy = NoProxy::new(self.no_proxy.unwrap_or_default())
            .map_err(|err| ConfigError::invalid(err.to_string()))?;

        let timeouts = self
            .timeouts
            .map(RawTimeouts::resolve)
            .transpose()?
            .unwrap_or_default();

        let log_level = overrides
            .log_level
            .or(self.log.and_then(|log| log.level))
            .unwrap_or_default();

        Ok(Config {
            listen,
            parents,
            credentials,
            access,
            no_proxy,
            timeouts,
            log_level,
        })
    }
}

/// 1-based line and column of a byte offset.
fn line_column(source: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(source.len());
    let before = source.get(..offset).unwrap_or_default();
    let line = before.matches('\n').count() + 1;
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |last| last.chars().count())
        + 1;
    (line, column)
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn load(toml: &str) -> Result<Config, ConfigError> {
        Config::from_toml_str(toml, Overrides::default())
    }

    fn error_text(toml: &str) -> String {
        load(toml).unwrap_err().to_string()
    }

    const FULL: &str = r#"
        listen = ["127.0.0.1:3128", "[::1]:3128"]
        parents = ["proxy1.example.com:8080", "proxy2.example.com:8080"]

        [credentials]
        username = "alice"
        domain = "EXAMPLE"
        workstation = "LAPTOP"
        method = "ntlm2sr"
        password = "hunter2-secret"

        [log]
        level = "debug"
    "#;

    #[test]
    fn empty_config_uses_defaults() {
        let config = load("").unwrap();
        assert_eq!(config.listen, vec!["127.0.0.1:3128".parse().unwrap()]);
        assert!(config.parents.is_empty());
        assert!(config.credentials.is_none());
        assert_eq!(config.log_level, LogLevel::Info);
    }

    #[test]
    fn parses_a_full_config() {
        let config = load(FULL).unwrap();
        assert_eq!(config.listen.len(), 2);
        assert_eq!(config.parents[1].to_string(), "proxy2.example.com:8080");
        assert_eq!(config.log_level, LogLevel::Debug);

        let creds = config.credentials.unwrap();
        assert_eq!(creds.username, "alice");
        assert_eq!(creds.domain, "EXAMPLE");
        assert_eq!(creds.workstation.as_deref(), Some("LAPTOP"));
        assert_eq!(creds.method, AuthMethod::Ntlm2sr);
        match creds.secret {
            Some(Secret::Password(p)) => assert_eq!(p.expose_secret(), "hunter2-secret"),
            other => panic!("unexpected secret: {other:?}"),
        }
    }

    #[test]
    fn method_defaults_to_ntlmv2() {
        let config = load("[credentials]\nusername = \"a\"\npassword = \"p\"").unwrap();
        assert_eq!(config.credentials.unwrap().method, AuthMethod::Ntlmv2);
    }

    #[test]
    fn accepts_an_nt_hash() {
        let hash = "8846f7eaee8fb117ad06bdd830b7586c";
        let config = load(&format!(
            "[credentials]\nusername = \"a\"\nnt_hash = \"{hash}\""
        ))
        .unwrap();
        match config.credentials.unwrap().secret {
            Some(Secret::NtHash(bytes)) => {
                assert_eq!(hex::encode(bytes.expose_secret()), hash);
            }
            other => panic!("unexpected secret: {other:?}"),
        }
    }

    #[test]
    fn negotiate_needs_no_secret() {
        let config = load("[credentials]\nmethod = \"negotiate\"").unwrap();
        let creds = config.credentials.unwrap();
        assert_eq!(creds.method, AuthMethod::Negotiate);
        assert!(creds.secret.is_none());
    }

    #[test]
    fn rejects_unknown_fields() {
        for toml in [
            "listn = []",
            "[credentials]\nusername = \"a\"\npasword = \"x\"",
            "[log]\nlevl = \"info\"",
        ] {
            let text = error_text(toml);
            assert!(text.contains("unknown field"), "{toml:?} -> {text}");
        }
    }

    #[test]
    fn syntax_errors_report_the_location() {
        let text = error_text("listen = [\"127.0.0.1:3128\"]\n= broken");
        assert!(text.contains("<string>:2:"), "{text}");
    }

    #[test]
    fn rejects_bad_addresses() {
        assert!(load("listen = [\"not-an-address\"]").is_err());
        assert!(load("listen = []").is_err());
        assert!(load("listen = [\"127.0.0.1:1\", \"127.0.0.1:1\"]").is_err());
        assert!(load("parents = [\"proxy\"]").is_err());
        assert!(load("parents = [\"http://proxy:8080\"]").is_err());
    }

    #[test]
    fn rejects_incoherent_credentials() {
        let cases = [
            ("[credentials]\npassword = \"p\"", "username is required"),
            (
                "[credentials]\nusername = \"a\"",
                "password or credentials.nt_hash is required",
            ),
            (
                "[credentials]\nusername = \"a\"\npassword = \"p\"\nnt_hash = \"8846f7eaee8fb117ad06bdd830b7586c\"",
                "mutually exclusive",
            ),
            (
                "[credentials]\nusername = \"a\"\npassword = \"\"",
                "must not be empty",
            ),
            (
                "[credentials]\nusername = \"a\"\nnt_hash = \"abcd\"",
                "32 hexadecimal",
            ),
            (
                "[credentials]\nusername = \"a\"\nnt_hash = \"zz46f7eaee8fb117ad06bdd830b7586c\"",
                "32 hexadecimal",
            ),
            (
                "[credentials]\nmethod = \"negotiate\"\npassword = \"p\"",
                "logged-in identity",
            ),
            (
                "[credentials]\nmethod = \"kerberos\"\nusername = \"a\"",
                "unknown variant",
            ),
        ];
        for (toml, expected) in cases {
            let text = error_text(toml);
            assert!(text.contains(expected), "{toml:?} -> {text}");
        }
    }

    #[test]
    fn command_line_overrides_the_file() {
        let overrides = Overrides {
            listen: vec!["0.0.0.0:9999".parse().unwrap()],
            parents: vec!["other.example.com:3128".parse().unwrap()],
            username: Some("bob".into()),
            domain: Some("OTHER".into()),
            method: Some(AuthMethod::Nt),
            password: Some(SecretString::from("prompted".to_owned())),
            log_level: Some(LogLevel::Trace),
        };
        let config = Config::from_toml_str(FULL, overrides).unwrap();

        assert_eq!(config.listen, vec!["0.0.0.0:9999".parse().unwrap()]);
        assert_eq!(config.parents.len(), 1);
        assert_eq!(config.parents[0].host, "other.example.com");
        assert_eq!(config.log_level, LogLevel::Trace);

        let creds = config.credentials.unwrap();
        assert_eq!(creds.username, "bob");
        assert_eq!(creds.domain, "OTHER");
        assert_eq!(creds.method, AuthMethod::Nt);
        assert_eq!(creds.workstation.as_deref(), Some("LAPTOP"));
        match creds.secret {
            Some(Secret::Password(p)) => assert_eq!(p.expose_secret(), "prompted"),
            other => panic!("unexpected secret: {other:?}"),
        }
    }

    #[test]
    fn a_prompted_password_replaces_a_file_hash() {
        let toml =
            "[credentials]\nusername = \"a\"\nnt_hash = \"8846f7eaee8fb117ad06bdd830b7586c\"";
        let overrides = Overrides {
            password: Some(SecretString::from("prompted".to_owned())),
            ..Overrides::default()
        };
        let creds = Config::from_toml_str(toml, overrides)
            .unwrap()
            .credentials
            .unwrap();
        assert_eq!(creds.secret.unwrap().kind(), "password");
    }

    #[test]
    fn command_line_alone_can_define_credentials() {
        let overrides = Overrides {
            username: Some("bob".into()),
            password: Some(SecretString::from("p".to_owned())),
            ..Overrides::default()
        };
        let creds = Config::from_toml_str("", overrides)
            .unwrap()
            .credentials
            .unwrap();
        assert_eq!(creds.username, "bob");
        assert_eq!(creds.method, AuthMethod::Ntlmv2);
    }

    #[test]
    fn secrets_never_appear_in_debug_or_summary() {
        let hash = "8846f7eaee8fb117ad06bdd830b7586c";
        for toml in [
            FULL.to_owned(),
            format!("[credentials]\nusername = \"a\"\nnt_hash = \"{hash}\""),
        ] {
            let config = load(&toml).unwrap();
            for text in [format!("{config:?}"), config.summary()] {
                assert!(!text.contains("hunter2-secret"), "{text}");
                assert!(!text.contains(hash), "{text}");
            }
        }
        assert!(format!("{:?}", load(FULL).unwrap()).contains("REDACTED"));
    }

    #[test]
    fn errors_never_echo_secret_values() {
        let cases = [
            // wrong type: serde would normally print the integer
            "[credentials]\nusername = \"a\"\npassword = 123456789",
            "[credentials]\nusername = \"a\"\npassword = true",
            // invalid hash value
            "[credentials]\nusername = \"a\"\nnt_hash = \"not-a-hash-topsecret\"",
            // syntax error on the very line that holds the secret
            "[credentials]\nusername = \"a\"\npassword = \"topsecret\" garbage",
        ];
        for toml in cases {
            let text = error_text(toml);
            for secret in ["123456789", "topsecret", "true"] {
                assert!(!text.contains(secret), "{toml:?} leaked {secret:?}: {text}");
            }
        }
    }

    #[test]
    fn access_and_no_proxy_default_to_open_and_empty() {
        let config = load("").unwrap();
        assert!(config.access.rules().is_empty());
        assert_eq!(config.access.default_action(), Action::Allow);
        assert!(config.no_proxy.entries().is_empty());
    }

    #[test]
    fn parses_access_rules_in_order() {
        let config = load(
            r#"
            [access]
            default = "deny"
            rules = [
                { allow = "127.0.0.1" },
                { allow = "10.0.0.0/8" },
                { deny = "*" },
            ]
            "#,
        )
        .unwrap();

        assert_eq!(config.access.default_action(), Action::Deny);
        let shown: Vec<_> = config
            .access
            .rules()
            .iter()
            .map(|rule| format!("{} {}", rule.action.as_str(), rule.source))
            .collect();
        assert_eq!(shown, ["allow 127.0.0.1/32", "allow 10.0.0.0/8", "deny *"]);
        assert_eq!(
            config.access.check("10.1.2.3".parse().unwrap()),
            Action::Allow
        );
        assert_eq!(
            config.access.check("192.0.2.1".parse().unwrap()),
            Action::Deny
        );
    }

    #[test]
    fn rejects_invalid_access_configuration() {
        let cases = [
            (
                "[access]\nrules = [{ allow = \"example.com\" }]",
                "host names are not supported",
            ),
            (
                "[access]\nrules = [{ allow = \"10.0.0.0/40\" }]",
                "invalid access rule source",
            ),
            (
                "[access]\nrules = [{ permit = \"10.0.0.0/8\" }]",
                "unknown variant",
            ),
            (
                "[access]\nrules = [{ allow = \"10.0.0.1\", deny = \"*\" }]",
                "invalid config at <string>:2:",
            ),
            ("[access]\ndefault = \"maybe\"", "unknown variant"),
            ("[access]\nrule = []", "unknown field"),
        ];
        for (toml, expected) in cases {
            let text = error_text(toml);
            assert!(text.contains(expected), "{toml:?} -> {text}");
        }
    }

    #[test]
    fn parses_no_proxy_entries() {
        let config =
            load(r#"no_proxy = ["localhost", "*.corp.example.com", "10.0.0.0/8"]"#).unwrap();
        assert!(config.no_proxy.matches("LocalHost"));
        assert!(config.no_proxy.matches("intranet.corp.example.com"));
        assert!(config.no_proxy.matches("10.9.8.7"));
        assert!(!config.no_proxy.matches("example.com"));
    }

    #[test]
    fn rejects_invalid_no_proxy_entries() {
        let text = error_text(r#"no_proxy = ["localhost", "[unclosed"]"#);
        assert!(text.contains("[unclosed"), "{text}");
        assert!(error_text(r#"no_proxy = [""]"#).contains("must not be empty"));
    }

    #[test]
    fn the_summary_describes_access_and_no_proxy() {
        let config = load(
            "no_proxy = [\"localhost\"]\n[access]\ndefault = \"deny\"\nrules = [{ allow = \"10.0.0.0/8\" }]",
        )
        .unwrap();
        let summary = config.summary();
        assert!(
            summary.contains("default deny; first match wins: allow 10.0.0.0/8"),
            "{summary}"
        );
        assert!(summary.contains("no_proxy:    localhost"), "{summary}");
        assert!(
            load("")
                .unwrap()
                .summary()
                .contains("default allow, no rules")
        );
    }

    #[test]
    fn timeouts_have_defaults_and_can_be_overridden() {
        assert_eq!(load("").unwrap().timeouts, Timeouts::default());

        let config = load("[timeouts]\nconnect_secs = 3\ntunnel_idle_secs = 90").unwrap();
        assert_eq!(config.timeouts.connect, Duration::from_secs(3));
        assert_eq!(config.timeouts.tunnel_idle, Duration::from_secs(90));
        assert_eq!(config.timeouts.client_idle, Timeouts::default().client_idle);
    }

    #[test]
    fn rejects_invalid_timeouts() {
        for toml in [
            "[timeouts]\nconnect_secs = 0",
            "[timeouts]\nclient_idle_secs = 86401",
            "[timeouts]\ntunnel_idle_secs = -5",
            "[timeouts]\nconnect = 5",
        ] {
            assert!(load(toml).is_err(), "should reject {toml:?}");
        }
        assert!(error_text("[timeouts]\nconnect_secs = 0").contains("timeouts.connect_secs"));
    }

    #[test]
    fn line_column_is_one_based() {
        assert_eq!(line_column("abc", 0), (1, 1));
        assert_eq!(line_column("abc\ndef", 5), (2, 2));
        assert_eq!(line_column("é\nx", 3), (2, 1));
        assert_eq!(line_column("abc", 99), (1, 4));
    }

    #[test]
    fn load_reports_missing_files() {
        let err = Config::load(
            Some(Path::new("/nonexistent/gatir.toml")),
            Overrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot read config file"), "{err}");
    }
}
