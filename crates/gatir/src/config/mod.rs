//! Configuration: TOML file, overridden by command-line options.
//!
//! Precedence, highest first: command line, config file, built-in defaults.
//! A command-line value replaces the file value; lists are not merged.

mod addr;
mod credentials;
mod headers;
mod socks5;
mod tunnel;

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

pub use addr::{HostPort, HostPortError};
pub use credentials::{AuthMethod, Credentials, NT_HASH_LEN, Secret};
use credentials::{RawCredentials, SecretValue};
pub use headers::HeaderRule;
pub use socks5::{Socks5, Socks5Credentials};
pub use tunnel::{Tunnel, TunnelError};

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
    pub parents: Vec<HostPort>,
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
    /// Local ports whose connections are carried to a fixed destination.
    pub tunnels: Vec<Tunnel>,
    /// A SOCKS5 server, if one is wanted.
    pub socks5: Option<Socks5>,
    pub timeouts: Timeouts,
    pub log_level: LogLevel,
}

/// Values that take precedence over the config file.
#[derive(Debug, Default)]
pub struct Overrides {
    pub listen: Vec<SocketAddr>,
    pub parents: Vec<HostPort>,
    /// A PAC file or address. Like `parents`, it is a way of finding the proxy,
    /// so it replaces the other one in the file.
    pub pac: Option<PacLocation>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub method: Option<AuthMethod>,
    /// A password supplied interactively. Replaces any password or hash
    /// from the config file.
    pub password: Option<SecretString>,
    /// Replaces the tunnels of the file.
    pub tunnels: Vec<Tunnel>,
    /// Addresses for a SOCKS5 server. Replace those of the file.
    pub socks5: Vec<SocketAddr>,
    pub log_level: Option<LogLevel>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: Option<Vec<SocketAddr>>,
    parents: Option<Vec<HostPort>>,
    pac: Option<RawPac>,
    credentials: Option<RawCredentials>,
    access: Option<RawAccess>,
    no_proxy: Option<Vec<String>>,
    headers: Option<BTreeMap<String, SecretValue>>,
    tunnels: Option<Vec<tunnel::RawTunnel>>,
    socks5: Option<socks5::RawSocks5>,
    timeouts: Option<RawTimeouts>,
    log: Option<RawLog>,
}

/// Where a PAC script is read from.
#[derive(Clone, PartialEq, Eq)]
pub enum PacLocation {
    File(PathBuf),
    /// An `http://` or `https://` address.
    Url(String),
}

impl PacLocation {
    /// The address without its query and fragment, which may hold a token.
    fn shown(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Url(url) => url.split(['?', '#']).next().unwrap_or_default().to_owned(),
        }
    }

    fn url(text: &str) -> Result<Self, ConfigError> {
        let invalid = || {
            ConfigError::invalid(
                "the PAC address must be http:// or https:// followed by a host, with no user \
                 name or password in it",
            )
        };
        let uri: hyper::Uri = text.parse().map_err(|_| invalid())?;
        let scheme_ok = matches!(uri.scheme_str(), Some("http" | "https"));
        let authority_ok = uri.authority().is_some_and(|authority| {
            !authority.as_str().contains('@') && !authority.host().is_empty()
        });
        if scheme_ok && authority_ok {
            Ok(Self::Url(text.to_owned()))
        } else {
            Err(invalid())
        }
    }
}

/// A text that starts with `http://` or `https://` is an address, anything
/// else is a file.
impl std::str::FromStr for PacLocation {
    type Err = ConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            Self::url(text)
        } else if text.is_empty() {
            Err(ConfigError::invalid("the PAC file must not be empty"))
        } else {
            Ok(Self::File(PathBuf::from(text)))
        }
    }
}

impl std::fmt::Display for PacLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.shown())
    }
}

impl std::fmt::Debug for PacLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(_) => write!(f, "File({:?})", self.shown()),
            Self::Url(_) => write!(f, "Url({:?})", self.shown()),
        }
    }
}

/// Where the PAC script comes from, its limits, and its name lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacConfig {
    pub location: PacLocation,
    /// How often the script is read again to see if it changed.
    pub refresh: Duration,
    /// How long to wait for a PAC script to be fetched from an address.
    pub fetch_timeout: Duration,
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
    pub fn with_defaults(location: PacLocation) -> Self {
        // A file is cheap to read again, and edited by hand: look often.
        let refresh = match location {
            PacLocation::File(_) => Duration::from_secs(60),
            PacLocation::Url(_) => Duration::from_secs(3600),
        };
        Self {
            location,
            refresh,
            fetch_timeout: Duration::from_secs(15),
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
    url: Option<String>,
    refresh_secs: Option<u64>,
    fetch_timeout_secs: Option<u64>,
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
    /// `from_command_line` is the location given on the command line, if any,
    /// which replaces the one in the file. A path in the file is relative to the
    /// file that holds it.
    fn resolve(
        self,
        from_command_line: Option<PacLocation>,
        base: Option<&Path>,
    ) -> Result<PacConfig, ConfigError> {
        let location = match (from_command_line, self.file, self.url) {
            (Some(location), _, _) => location,
            (None, Some(_), Some(_)) => {
                return Err(ConfigError::invalid(
                    "pac.file and pac.url cannot both be set: they are two places to read the \
                     script from",
                ));
            }
            (None, Some(file), None) => {
                if file.as_os_str().is_empty() {
                    return Err(ConfigError::invalid("pac.file must not be empty"));
                }
                match base {
                    Some(base) if file.is_relative() => PacLocation::File(base.join(file)),
                    _ => PacLocation::File(file),
                }
            }
            (None, None, Some(url)) => PacLocation::url(&url)?,
            (None, None, None) => {
                return Err(ConfigError::invalid(
                    "pac.file or pac.url is required in the [pac] table",
                ));
            }
        };
        let mut pac = PacConfig::with_defaults(location);
        if let Some(secs) = self.refresh_secs {
            pac.refresh = Duration::from_secs(within("refresh_secs", secs, 1, 604_800)?);
        }
        if let Some(secs) = self.fetch_timeout_secs {
            pac.fetch_timeout = Duration::from_secs(within("fetch_timeout_secs", secs, 1, 300)?);
        }
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
            (Some(pac), _) => format!("chosen by the PAC script at {}", pac.location),
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
        let tunnels = if self.tunnels.is_empty() {
            "none".to_owned()
        } else {
            join(self.tunnels.iter())
        };
        let socks5 = match &self.socks5 {
            None => "none".to_owned(),
            Some(socks5) => format!(
                "{}, {}",
                join(socks5.listen.iter()),
                match &socks5.credentials {
                    None => "no user name or password asked".to_owned(),
                    Some(credentials) => format!(
                        "user name {:?} and a password asked, password hidden",
                        credentials.username
                    ),
                }
            ),
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
             access:      {access}\nno_proxy:    {no_proxy}\nheaders:     {headers} (set on every request)\ntunnels:     {tunnels}\nsocks5:      {socks5}\n\
             timeouts:    {timeouts}\nlog level:   {}",
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

        let tunnels: Vec<Tunnel> = if overrides.tunnels.is_empty() {
            self.tunnels
                .unwrap_or_default()
                .into_iter()
                .map(Tunnel::from)
                .collect()
        } else {
            overrides.tunnels
        };
        let socks5 = match (self.socks5, overrides.socks5.is_empty()) {
            (Some(raw), _) => Some(raw.resolve(overrides.socks5)?),
            (None, false) => Some(Socks5::open(overrides.socks5)),
            (None, true) => None,
        };
        // Two listeners cannot share an address.
        let taken = listen
            .iter()
            .chain(tunnels.iter().map(|tunnel| &tunnel.listen))
            .chain(socks5.iter().flat_map(|socks5| &socks5.listen));
        for (i, addr) in taken.clone().enumerate() {
            // Port 0 asks for any free port, so it cannot clash.
            if addr.port() != 0 && taken.clone().take(i).any(|earlier| earlier == addr) {
                return Err(ConfigError::invalid(format!(
                    "the address {addr} is used by more than one listener"
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
            tunnels,
            socks5,
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
            tunnels: Vec::new(),
            socks5: Vec::new(),
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
        assert_eq!(pac, PacConfig::with_defaults(file_location("proxy.pac")));
        assert_eq!(pac.refresh, Duration::from_secs(60));
        assert!(config.parents.is_empty());
        assert!(load("").unwrap().pac.is_none());
    }

    fn file_location(path: &str) -> PacLocation {
        PacLocation::File(PathBuf::from(path))
    }

    #[test]
    fn a_pac_table_can_name_an_address_instead() {
        let config = load("[pac]\nurl = \"https://pac.example.com/proxy.pac\"").unwrap();
        let pac = config.pac.unwrap();
        assert_eq!(
            pac.location,
            PacLocation::Url("https://pac.example.com/proxy.pac".into())
        );
        // An address changes rarely, and each look costs a request.
        assert_eq!(pac.refresh, Duration::from_secs(3600));
        assert_eq!(pac.fetch_timeout, Duration::from_secs(15));
    }

    #[test]
    fn how_often_and_how_long_to_fetch_can_be_set() {
        let config = load(
            "[pac]\nurl = \"http://pac.example.com/p\"\nrefresh_secs = 90\n\
             fetch_timeout_secs = 4",
        )
        .unwrap();
        let pac = config.pac.unwrap();
        assert_eq!(pac.refresh, Duration::from_secs(90));
        assert_eq!(pac.fetch_timeout, Duration::from_secs(4));
    }

    #[test]
    fn a_text_is_an_address_only_if_it_starts_like_one() {
        for text in [
            "http://h/p.pac",
            "HTTPS://h:8443/p.pac?x=1",
            "https://[::1]/p",
        ] {
            assert!(matches!(text.parse(), Ok(PacLocation::Url(_))), "{text}");
        }
        for text in [
            "proxy.pac",
            "/etc/proxy.pac",
            "C:\\pac\\p.pac",
            "./http/p.pac",
        ] {
            assert!(matches!(text.parse(), Ok(PacLocation::File(_))), "{text}");
        }
        for text in [
            "http://",
            "https:///p.pac",
            "http://user:secret@h/p.pac",
            "http://h with space/p",
            "",
        ] {
            assert!(text.parse::<PacLocation>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn a_pac_address_is_shown_without_its_query() {
        let location: PacLocation = "https://h.example.com/p.pac?token=hush#frag"
            .parse()
            .unwrap();
        assert_eq!(location.to_string(), "https://h.example.com/p.pac");
        assert!(!format!("{location:?}").contains("hush"));
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
            ("[pac]", "pac.file or pac.url is required"),
            (
                "[pac]\nfile = \"a\"\nurl = \"http://h/p\"",
                "pac.file and pac.url cannot both be set",
            ),
            ("[pac]\nurl = \"ftp://h/p\"", "must be http:// or https://"),
            ("[pac]\nurl = \"h/p\"", "must be http:// or https://"),
            (
                "[pac]\nurl = \"http://user:pw@h/p\"",
                "no user name or password",
            ),
            (
                "[pac]\nurl = \"http://h/p\"\nrefresh_secs = 0",
                "pac.refresh_secs must be between",
            ),
            (
                "[pac]\nurl = \"http://h/p\"\nfetch_timeout_secs = 301",
                "pac.fetch_timeout_secs must be between",
            ),
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
                pac: Some(file_location("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap();
        assert!(config.parents.is_empty());
        assert_eq!(config.pac.unwrap().location, file_location("cli.pac"));

        // A script named on the command line keeps the limits set in the file.
        let config = Config::from_toml_str(
            "[pac]\nfile = \"file.pac\"\nworkers = 2",
            Overrides {
                pac: Some(file_location("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap();
        let pac = config.pac.unwrap();
        assert_eq!((pac.location, pac.workers), (file_location("cli.pac"), 2));

        // An address on the command line takes the place of a file in the file.
        let config = Config::from_toml_str(
            "[pac]\nfile = \"file.pac\"",
            Overrides {
                pac: Some("http://h.example.com/p.pac".parse().unwrap()),
                ..Overrides::default()
            },
        )
        .unwrap();
        let pac = config.pac.unwrap();
        assert!(matches!(pac.location, PacLocation::Url(_)));
        assert_eq!(pac.refresh, Duration::from_secs(3600));

        // Both on the command line is a mistake.
        let error = Config::from_toml_str(
            "",
            Overrides {
                parents: vec!["cli.example.com:2".parse().unwrap()],
                pac: Some(file_location("cli.pac")),
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
        assert_eq!(
            config.pac.unwrap().location,
            PacLocation::File(dir.path().join("rules/proxy.pac"))
        );

        // An absolute path is left as it is, and so is one from the command line.
        let absolute = dir.path().join("elsewhere.pac");
        std::fs::write(
            &file,
            format!("[pac]\nfile = {:?}", absolute.display().to_string()),
        )
        .unwrap();
        let config = Config::load(Some(&file), Overrides::default()).unwrap();
        assert_eq!(config.pac.unwrap().location, PacLocation::File(absolute));

        let config = Config::load(
            Some(&file),
            Overrides {
                pac: Some(file_location("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap();
        assert_eq!(config.pac.unwrap().location, file_location("cli.pac"));
    }

    #[test]
    fn the_summary_says_that_a_pac_script_chooses() {
        let summary = load("[pac]\nfile = \"proxy.pac\"").unwrap().summary();
        assert!(
            summary.contains("chosen by the PAC script at proxy.pac"),
            "{summary}"
        );

        let summary = load("[pac]\nurl = \"https://h.example.com/p.pac?token=hush\"")
            .unwrap()
            .summary();
        assert!(
            summary.contains("chosen by the PAC script at https://h.example.com/p.pac"),
            "{summary}"
        );
        assert!(!summary.contains("hush"), "{summary}");
    }

    #[test]
    fn tunnels_are_listed_as_tables() {
        let config = load(
            "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"git.example.com:22\"\n\
             [[tunnels]]\nlisten = \"[::1]:8443\"\ntarget = \"[2001:db8::1]:443\"",
        )
        .unwrap();
        let shown: Vec<String> = config.tunnels.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                "127.0.0.1:2222 -> git.example.com:22",
                "[::1]:8443 -> [2001:db8::1]:443"
            ]
        );
        assert!(load("").unwrap().tunnels.is_empty());
        assert!(
            config
                .summary()
                .contains("tunnels:     127.0.0.1:2222 -> git.example.com:22, ")
        );
        assert!(load("").unwrap().summary().contains("tunnels:     none"));
    }

    #[test]
    fn rejects_tunnels_that_make_no_sense() {
        for (toml, expected) in [
            ("[[tunnels]]\nlisten = \"127.0.0.1:2222\"", "missing field"),
            ("[[tunnels]]\ntarget = \"git:22\"", "missing field"),
            (
                "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"git\"",
                "invalid address",
            ),
            (
                "[[tunnels]]\nlisten = \"2222\"\ntarget = \"git:22\"",
                "invalid socket address",
            ),
            (
                "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"git:22\"\nsecret = 1",
                "unknown field",
            ),
            (
                "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"a:22\"\n\
                 [[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"b:22\"",
                "127.0.0.1:2222 is used by more than one listener",
            ),
            (
                "listen = [\"127.0.0.1:3128\"]\n[[tunnels]]\nlisten = \"127.0.0.1:3128\"\ntarget = \"a:22\"",
                "127.0.0.1:3128 is used by more than one listener",
            ),
        ] {
            let text = error_text(toml);
            assert!(text.contains(expected), "{toml:?} -> {text}");
        }
    }

    #[test]
    fn tunnels_on_the_command_line_replace_those_of_the_file() {
        let file = "[[tunnels]]\nlisten = \"127.0.0.1:2222\"\ntarget = \"file.example.com:22\"";
        let config = Config::from_toml_str(
            file,
            Overrides {
                tunnels: vec!["3333:cli.example.com:22".parse().unwrap()],
                ..Overrides::default()
            },
        )
        .unwrap();
        assert_eq!(config.tunnels.len(), 1);
        assert_eq!(config.tunnels[0].target.host, "cli.example.com");
        // Without any on the command line, the file's stay.
        let config = Config::from_toml_str(file, Overrides::default()).unwrap();
        assert_eq!(config.tunnels[0].target.host, "file.example.com");
    }

    #[test]
    fn a_socks5_server_is_a_table_with_addresses_and_maybe_a_password() {
        let open = load("[socks5]\nlisten = [\"127.0.0.1:1080\", \"[::1]:1080\"]")
            .unwrap()
            .socks5
            .unwrap();
        assert_eq!(open.listen.len(), 2);
        assert!(open.credentials.is_none());
        assert!(load("").unwrap().socks5.is_none());

        let config = load(
            "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"\npassword = \"s3cret-socks\"",
        )
        .unwrap();
        let credentials = config
            .socks5
            .as_ref()
            .unwrap()
            .credentials
            .as_ref()
            .unwrap();
        assert_eq!(credentials.username, "bob");
        assert!(credentials.verify(b"bob", b"s3cret-socks"));
        assert!(!credentials.verify(b"bob", b"other"));

        // The password is never shown.
        for text in [format!("{config:?}"), config.summary()] {
            assert!(!text.contains("s3cret-socks"), "{text}");
        }
        assert!(config.summary().contains("user name \"bob\""));
        assert!(load("").unwrap().summary().contains("socks5:      none"));
        let summary = load("[socks5]\nlisten = [\"127.0.0.1:1080\"]")
            .unwrap()
            .summary();
        assert!(summary.contains("socks5:      127.0.0.1:1080, no user name or password asked"));
    }

    #[test]
    fn rejects_a_socks5_table_that_makes_no_sense() {
        let long = "x".repeat(256);
        for (toml, expected) in [
            ("[socks5]", "socks5.listen must name at least one address"),
            (
                "[socks5]\nlisten = []",
                "socks5.listen must name at least one address",
            ),
            (
                "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"",
                "socks5.username and socks5.password go together",
            ),
            (
                "[socks5]\nlisten = [\"127.0.0.1:1080\"]\npassword = \"pw\"",
                "socks5.username and socks5.password go together",
            ),
            (
                "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"\"\npassword = \"pw\"",
                "socks5.username must be between 1 and 255 bytes",
            ),
            (
                "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"\npassword = \"\"",
                "socks5.password must be between 1 and 255 bytes",
            ),
            (
                "[socks5]\nlisten = [\"127.0.0.1\"]",
                "invalid socket address",
            ),
            (
                "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nport = 1",
                "unknown field",
            ),
            (
                "listen = [\"127.0.0.1:3128\"]\n[socks5]\nlisten = [\"127.0.0.1:3128\"]",
                "127.0.0.1:3128 is used by more than one listener",
            ),
            (
                "[socks5]\nlisten = [\"127.0.0.1:1080\", \"127.0.0.1:1080\"]",
                "127.0.0.1:1080 is used by more than one listener",
            ),
            (
                "[[tunnels]]\nlisten = \"127.0.0.1:1080\"\ntarget = \"a:22\"\n\
                 [socks5]\nlisten = [\"127.0.0.1:1080\"]",
                "127.0.0.1:1080 is used by more than one listener",
            ),
        ] {
            let text = error_text(toml);
            assert!(text.contains(expected), "{toml:?} -> {text}");
        }
        let text = error_text(&format!(
            "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"\npassword = \"{long}\""
        ));
        assert!(
            text.contains("between 1 and 255 bytes") && !text.contains(&long),
            "{text}"
        );
    }

    #[test]
    fn a_socks5_password_is_never_echoed_by_an_error() {
        for toml in [
            "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"\npassword = 123456789",
            "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"\npassword = true",
            "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"\npassword = \"topsecret\" garbage",
        ] {
            let text = error_text(toml);
            for secret in ["123456789", "topsecret", "true"] {
                assert!(!text.contains(secret), "{toml:?} leaked {secret:?}: {text}");
            }
        }
    }

    #[test]
    fn the_command_line_names_the_addresses_of_the_socks5_server() {
        let file = "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"bob\"\npassword = \"pw\"";
        // It replaces the addresses and keeps who may use it.
        let config = Config::from_toml_str(
            file,
            Overrides {
                socks5: vec!["127.0.0.1:2080".parse().unwrap()],
                ..Overrides::default()
            },
        )
        .unwrap();
        let socks5 = config.socks5.unwrap();
        assert_eq!(socks5.listen, vec!["127.0.0.1:2080".parse().unwrap()]);
        assert!(socks5.credentials.is_some());

        // Without a table in the file, the server asks for nothing.
        let config = Config::from_toml_str(
            "",
            Overrides {
                socks5: vec!["127.0.0.1:2080".parse().unwrap()],
                ..Overrides::default()
            },
        )
        .unwrap();
        assert!(config.socks5.unwrap().credentials.is_none());
        // And a table with no address is completed by it.
        let config = Config::from_toml_str(
            "[socks5]\nusername = \"bob\"\npassword = \"pw\"",
            Overrides {
                socks5: vec!["127.0.0.1:2080".parse().unwrap()],
                ..Overrides::default()
            },
        )
        .unwrap();
        assert!(config.socks5.unwrap().credentials.is_some());
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
