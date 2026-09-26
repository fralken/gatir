//! Configuration: TOML file, overridden by command-line options.
//!
//! Precedence, highest first: command line, config file, built-in defaults.
//! A command-line value replaces the file value; lists are not merged.

mod addr;
mod credentials;
mod headers;

use std::collections::BTreeMap;
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
pub use credentials::{AuthMethod, Credentials, NT_HASH_LEN, Secret};
use credentials::{RawCredentials, SecretValue};
pub use headers::HeaderRule;

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

/// Fully resolved and validated configuration.
#[derive(Debug)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
    /// Parent proxies in order of preference. Empty means direct connections,
    /// unless a PAC file chooses.
    pub parents: Vec<ParentAddr>,
    /// A PAC file that decides, for each request, which proxy to use. Not
    /// together with `parents`.
    pub pac: Option<PacConfig>,
    pub credentials: Option<Credentials>,
    /// Which client addresses may use the proxy.
    pub access: Acl,
    /// Destinations contacted directly instead of through a parent proxy.
    pub no_proxy: NoProxy,
    /// Header fields set on every forwarded request, replacing any the client
    /// sent. Values are sensitive.
    pub request_headers: Vec<HeaderRule>,
    pub timeouts: Timeouts,
    pub log_level: LogLevel,
}

/// Values that take precedence over the config file.
#[derive(Debug, Default)]
pub struct Overrides {
    pub listen: Vec<SocketAddr>,
    pub parents: Vec<ParentAddr>,
    /// A PAC file. Like `parents`, it is a way of finding the proxy, so it
    /// replaces the other one in the file.
    pub pac: Option<PathBuf>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub method: Option<AuthMethod>,
    /// A password supplied interactively. Replaces any password or hash
    /// from the config file.
    pub password: Option<SecretString>,
    pub log_level: Option<LogLevel>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: Option<Vec<SocketAddr>>,
    parents: Option<Vec<ParentAddr>>,
    pac: Option<RawPac>,
    credentials: Option<RawCredentials>,
    access: Option<RawAccess>,
    no_proxy: Option<Vec<String>>,
    headers: Option<BTreeMap<String, SecretValue>>,
    timeouts: Option<RawTimeouts>,
    log: Option<RawLog>,
}

/// The limits on a PAC script, and its name lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacConfig {
    pub file: PathBuf,
    /// How long one evaluation may take.
    pub time_limit: Duration,
    /// Memory one script engine may use, in bytes.
    pub memory_limit: usize,
    /// Script engines, so that this many evaluations can run at once.
    pub workers: usize,
    /// How long a script waits for a name lookup.
    pub dns_timeout: Duration,
    /// How long an answer to a name lookup is remembered.
    pub dns_ttl: Duration,
}

impl PacConfig {
    fn with_defaults(file: PathBuf) -> Self {
        Self {
            file,
            time_limit: Duration::from_secs(5),
            memory_limit: 64 * 1024 * 1024,
            workers: 4,
            dns_timeout: Duration::from_secs(2),
            dns_ttl: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPac {
    file: Option<PathBuf>,
    time_limit_ms: Option<u64>,
    memory_limit_mb: Option<u64>,
    workers: Option<u64>,
    dns_timeout_ms: Option<u64>,
    dns_ttl_secs: Option<u64>,
}

fn within(name: &str, value: u64, min: u64, max: u64) -> Result<u64, ConfigError> {
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::invalid(format!(
            "pac.{name} must be between {min} and {max}"
        )))
    }
}

impl RawPac {
    /// `file` is the path given on the command line, if any, which replaces the
    /// one in the file. A path in the file is relative to the file that holds it.
    fn resolve(self, file: Option<PathBuf>, base: Option<&Path>) -> Result<PacConfig, ConfigError> {
        let file = match (file, self.file) {
            (Some(from_command_line), _) => from_command_line,
            (None, Some(from_file)) => match base {
                Some(base) if from_file.is_relative() => base.join(from_file),
                _ => from_file,
            },
            (None, None) => {
                return Err(ConfigError::invalid(
                    "pac.file is required in the [pac] table",
                ));
            }
        };
        if file.as_os_str().is_empty() {
            return Err(ConfigError::invalid("pac.file must not be empty"));
        }
        let mut pac = PacConfig::with_defaults(file);
        if let Some(ms) = self.time_limit_ms {
            pac.time_limit = Duration::from_millis(within("time_limit_ms", ms, 10, 60_000)?);
        }
        if let Some(mb) = self.memory_limit_mb {
            pac.memory_limit = within("memory_limit_mb", mb, 4, 1024)? as usize * 1024 * 1024;
        }
        if let Some(workers) = self.workers {
            pac.workers = within("workers", workers, 1, 32)? as usize;
        }
        if let Some(ms) = self.dns_timeout_ms {
            pac.dns_timeout = Duration::from_millis(within("dns_timeout_ms", ms, 10, 30_000)?);
        }
        if let Some(secs) = self.dns_ttl_secs {
            pac.dns_ttl = Duration::from_secs(within("dns_ttl_secs", secs, 1, 86_400)?);
        }
        Ok(pac)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTimeouts {
    connect_secs: Option<u64>,
    client_idle_secs: Option<u64>,
    response_secs: Option<u64>,
    tunnel_idle_secs: Option<u64>,
    shutdown_grace_secs: Option<u64>,
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
        raw.resolve(overrides, path.and_then(Path::parent))
    }

    /// Like [`Config::load`], reading the TOML from a string.
    pub fn from_toml_str(source: &str, overrides: Overrides) -> Result<Self, ConfigError> {
        RawConfig::parse(source, "<string>")?.resolve(overrides, None)
    }

    /// A multi-line description that never includes secret values.
    pub fn summary(&self) -> String {
        let listen = join(self.listen.iter());
        let parents = match (&self.pac, self.parents.is_empty()) {
            (Some(pac), _) => format!("chosen by the PAC file {}", pac.file.display()),
            (None, true) => "none (direct connections)".to_owned(),
            (None, false) => join(self.parents.iter()),
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
        // Names only: the values are secrets.
        let headers = if self.request_headers.is_empty() {
            "none".to_owned()
        } else {
            join(self.request_headers.iter().map(|(name, _)| name))
        };
        let timeouts = format!(
            "connect {}s, client idle {}s, response {}s, tunnel idle {}s, shutdown grace {}s",
            self.timeouts.connect.as_secs(),
            self.timeouts.client_idle.as_secs(),
            self.timeouts.response.as_secs(),
            self.timeouts.tunnel_idle.as_secs(),
            self.timeouts.shutdown_grace.as_secs()
        );
        format!(
            "listen:      {listen}\nparents:     {parents}\ncredentials: {credentials}\n\
             access:      {access}\nno_proxy:    {no_proxy}\nheaders:     {headers} (set on every request)\ntimeouts:    {timeouts}\n\
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

    /// `base` is the directory of the configuration file, if it was read from one.
    fn resolve(self, overrides: Overrides, base: Option<&Path>) -> Result<Config, ConfigError> {
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

        // Parents and a PAC file are two ways of finding the proxy. Whichever
        // the command line names replaces the other one in the file.
        let (parents, pac) = match (overrides.parents.is_empty(), overrides.pac) {
            (false, Some(_)) => {
                return Err(ConfigError::invalid(
                    "--parent and --pac cannot be used together: the PAC file chooses the proxy",
                ));
            }
            (false, None) => (overrides.parents, None),
            (true, from_command_line @ Some(_)) => (
                Vec::new(),
                Some(
                    self.pac
                        .unwrap_or_default()
                        .resolve(from_command_line, base)?,
                ),
            ),
            (true, None) => (
                self.parents.unwrap_or_default(),
                self.pac.map(|raw| raw.resolve(None, base)).transpose()?,
            ),
        };
        if pac.is_some() && !parents.is_empty() {
            return Err(ConfigError::invalid(
                "parents and [pac] cannot both be set: the PAC file chooses the proxy",
            ));
        }

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
                raw.ntlmv2_hash = None;
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

        let request_headers = self
            .headers
            .map(headers::parse)
            .transpose()?
            .unwrap_or_default();

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
            pac,
            credentials,
            access,
            no_proxy,
            request_headers,
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
    fn accepts_an_ntlmv2_hash() {
        let hash = "dd4ee4752f859325fa0813cbfb374400";
        let config = load(&format!(
            "[credentials]\nusername = \"a\"\nntlmv2_hash = \"{hash}\""
        ))
        .unwrap();
        let creds = config.credentials.unwrap();
        assert_eq!(creds.method, AuthMethod::Ntlmv2);
        match creds.secret {
            Some(Secret::Ntlmv2Hash(bytes)) => {
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
    fn negotiate_can_name_the_service_of_the_parent() {
        let config = load(
            "[credentials]\nmethod = \"negotiate\"\nspn = \" HTTP/proxy.example.com@EXAMPLE.COM \"",
        )
        .unwrap();
        let creds = config.credentials.unwrap();
        assert_eq!(
            creds.spn.as_deref(),
            Some("HTTP/proxy.example.com@EXAMPLE.COM")
        );
        assert_eq!(
            load("[credentials]\nmethod = \"negotiate\"")
                .unwrap()
                .credentials
                .unwrap()
                .spn,
            None
        );
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
                "credentials.password, credentials.nt_hash or credentials.ntlmv2_hash is required",
            ),
            (
                "[credentials]\nusername = \"a\"\nmethod = \"nt\"",
                "credentials.password or credentials.nt_hash is required",
            ),
            (
                "[credentials]\nusername = \"a\"\nnt_hash = \"8846f7eaee8fb117ad06bdd830b7586c\"\nntlmv2_hash = \"8846f7eaee8fb117ad06bdd830b7586c\"",
                "mutually exclusive",
            ),
            (
                "[credentials]\nusername = \"a\"\nntlmv2_hash = \"abcd\"",
                "credentials.ntlmv2_hash must be exactly 32 hexadecimal",
            ),
            (
                "[credentials]\nusername = \"a\"\nmethod = \"nt\"\nntlmv2_hash = \"8846f7eaee8fb117ad06bdd830b7586c\"",
                "can only be used with method \"ntlmv2\"",
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
            (
                "[credentials]\nusername = \"a\"\npassword = \"p\"\nspn = \"HTTP@proxy\"",
                "credentials.spn only applies to method",
            ),
            (
                "[credentials]\nmethod = \"negotiate\"\nspn = \"  \"",
                "credentials.spn must not be empty",
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
            pac: None,
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
        for key in ["nt_hash", "ntlmv2_hash"] {
            let toml = format!(
                "[credentials]\nusername = \"a\"\n{key} = \"8846f7eaee8fb117ad06bdd830b7586c\""
            );
            let overrides = Overrides {
                password: Some(SecretString::from("prompted".to_owned())),
                ..Overrides::default()
            };
            let creds = Config::from_toml_str(&toml, overrides)
                .unwrap()
                .credentials
                .unwrap();
            assert_eq!(creds.secret.unwrap().kind(), "password", "{key}");
        }
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
            format!("[credentials]\nusername = \"a\"\nntlmv2_hash = \"{hash}\""),
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
            "[credentials]\nusername = \"a\"\nntlmv2_hash = \"not-a-hash-topsecret\"",
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
    fn parses_request_headers() {
        let config =
            load("[headers]\n\"User-Agent\" = \"corp/1.0\"\n\"X-Requested-By\" = \"gatir\"")
                .unwrap();
        let names: Vec<&str> = config
            .request_headers
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(names, ["user-agent", "x-requested-by"]);
        assert!(config.request_headers.iter().all(|(_, v)| v.is_sensitive()));
        assert!(
            config
                .summary()
                .contains("headers:     user-agent, x-requested-by")
        );
        assert!(load("").unwrap().request_headers.is_empty());
    }

    #[test]
    fn rejects_invalid_request_headers() {
        assert!(error_text("[headers]\nHost = \"example.com\"").contains("managed by gatir"));
        assert!(error_text("[headers]\n\"X-Thing\" = 12345").contains("quoted strings"));
    }

    #[test]
    fn header_values_never_appear_in_debug_summary_or_errors() {
        let config = load("[headers]\nX-Api-Key = \"super-secret-key\"").unwrap();
        for text in [format!("{config:?}"), config.summary()] {
            assert!(!text.contains("super-secret-key"), "{text}");
        }
        let text = error_text("[headers]\nX-Api-Key = 424242");
        assert!(!text.contains("424242"), "{text}");
        let text = error_text("[headers]\nHost = \"super-secret-key\"");
        assert!(!text.contains("super-secret-key"), "{text}");
    }

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

    #[test]
    fn a_pac_table_needs_only_a_file() {
        let config = load("[pac]\nfile = \"proxy.pac\"").unwrap();
        let pac = config.pac.unwrap();
        assert_eq!(pac, PacConfig::with_defaults(PathBuf::from("proxy.pac")));
        assert!(config.parents.is_empty());
        assert!(load("").unwrap().pac.is_none());
    }

    #[test]
    fn the_limits_of_a_pac_script_can_be_set() {
        let config = load(
            "[pac]\nfile = \"p.pac\"\ntime_limit_ms = 750\nmemory_limit_mb = 16\nworkers = 2\n\
             dns_timeout_ms = 300\ndns_ttl_secs = 5",
        )
        .unwrap();
        let pac = config.pac.unwrap();
        assert_eq!(pac.time_limit, Duration::from_millis(750));
        assert_eq!(pac.memory_limit, 16 * 1024 * 1024);
        assert_eq!(pac.workers, 2);
        assert_eq!(pac.dns_timeout, Duration::from_millis(300));
        assert_eq!(pac.dns_ttl, Duration::from_secs(5));
    }

    #[test]
    fn rejects_a_pac_table_that_makes_no_sense() {
        for (toml, expected) in [
            ("[pac]", "pac.file is required"),
            ("[pac]\nfile = \"\"", "pac.file must not be empty"),
            (
                "[pac]\nfile = \"p\"\ntime_limit_ms = 1",
                "pac.time_limit_ms must be between",
            ),
            (
                "[pac]\nfile = \"p\"\nmemory_limit_mb = 0",
                "pac.memory_limit_mb must be between",
            ),
            (
                "[pac]\nfile = \"p\"\nworkers = 0",
                "pac.workers must be between",
            ),
            (
                "[pac]\nfile = \"p\"\nworkers = 999",
                "pac.workers must be between",
            ),
            (
                "[pac]\nfile = \"p\"\ndns_ttl_secs = 0",
                "pac.dns_ttl_secs must be between",
            ),
            ("[pac]\nfile = \"p\"\nspeed = 1", "unknown field"),
            (
                "parents = [\"a.example.com:1\"]\n[pac]\nfile = \"p\"",
                "parents and [pac] cannot both be set",
            ),
        ] {
            let text = error_text(toml);
            assert!(text.contains(expected), "{toml:?} -> {text}");
        }
    }

    #[test]
    fn the_command_line_chooses_between_parents_and_a_pac_file() {
        let with_pac = "[pac]\nfile = \"file.pac\"";
        let with_parents = "parents = [\"file.example.com:1\"]";

        // Naming a parent drops the script of the file...
        let config = Config::from_toml_str(
            with_pac,
            Overrides {
                parents: vec!["cli.example.com:2".parse().unwrap()],
                ..Overrides::default()
            },
        )
        .unwrap();
        assert!(config.pac.is_none());
        assert_eq!(config.parents.len(), 1);

        // ...and naming a script drops the parents of the file.
        let config = Config::from_toml_str(
            with_parents,
            Overrides {
                pac: Some(PathBuf::from("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap();
        assert!(config.parents.is_empty());
        assert_eq!(config.pac.unwrap().file, PathBuf::from("cli.pac"));

        // A script named on the command line keeps the limits set in the file.
        let config = Config::from_toml_str(
            "[pac]\nfile = \"file.pac\"\nworkers = 2",
            Overrides {
                pac: Some(PathBuf::from("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap();
        let pac = config.pac.unwrap();
        assert_eq!((pac.file, pac.workers), (PathBuf::from("cli.pac"), 2));

        // Both on the command line is a mistake.
        let error = Config::from_toml_str(
            "",
            Overrides {
                parents: vec!["cli.example.com:2".parse().unwrap()],
                pac: Some(PathBuf::from("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("--parent and --pac cannot be used together"),
            "{error}"
        );
    }

    #[test]
    fn a_pac_path_in_the_file_is_relative_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gatir.toml");
        std::fs::write(&file, "[pac]\nfile = \"rules/proxy.pac\"").unwrap();

        let config = Config::load(Some(&file), Overrides::default()).unwrap();
        assert_eq!(config.pac.unwrap().file, dir.path().join("rules/proxy.pac"));

        // An absolute path is left as it is, and so is one from the command line.
        let absolute = dir.path().join("elsewhere.pac");
        std::fs::write(
            &file,
            format!("[pac]\nfile = {:?}", absolute.display().to_string()),
        )
        .unwrap();
        let config = Config::load(Some(&file), Overrides::default()).unwrap();
        assert_eq!(config.pac.unwrap().file, absolute);

        let config = Config::load(
            Some(&file),
            Overrides {
                pac: Some(PathBuf::from("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap();
        assert_eq!(config.pac.unwrap().file, PathBuf::from("cli.pac"));
    }

    #[test]
    fn the_summary_says_that_a_pac_file_chooses() {
        let summary = load("[pac]\nfile = \"proxy.pac\"").unwrap().summary();
        assert!(
            summary.contains("chosen by the PAC file proxy.pac"),
            "{summary}"
        );
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
