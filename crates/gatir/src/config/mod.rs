//! Configuration: TOML file, overridden by command-line options.
//!
//! Precedence, highest first: command line, config file, built-in defaults.
//! A command-line value replaces the file value; lists are not merged.

mod addr;
mod credentials;
mod headers;
mod location;
mod pac;
mod socks5;
mod summary;
mod timeouts;
mod tunnel;

#[cfg(test)]
mod testing;

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::acl::{Acl, Action, Rule};
use crate::noproxy::NoProxy;

pub use addr::{HostPort, HostPortError};
pub use credentials::{AuthMethod, Credentials, NT_HASH_LEN, Secret};
use credentials::{RawCredentials, SecretValue};
pub use headers::HeaderRule;
pub use location::{default_path, exposure};
use pac::RawPac;
pub use pac::{DEFAULT_FETCH_TIMEOUT, PacConfig, PacLocation};
pub use socks5::{Socks5, Socks5Credentials};
use timeouts::RawTimeouts;
pub use timeouts::Timeouts;
pub use tunnel::{Tunnel, TunnelError};

const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3128);

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The cause is part of the message, not a `source`: a reload logs only
    /// the message, and a `source` would make the command line print the cause
    /// a second time.
    #[error("cannot read config file {}: {error}", path.display())]
    Read {
        path: PathBuf,
        error: std::io::Error,
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
    /// Header fields set on every request sent through a parent, replacing any
    /// the client sent. Values are sensitive.
    pub request_headers: Vec<HeaderRule>,
    /// Local ports whose connections are carried to a fixed destination.
    pub tunnels: Vec<Tunnel>,
    /// A SOCKS5 server, if one is wanted.
    pub socks5: Option<Socks5>,
    pub timeouts: Timeouts,
    pub log_level: LogLevel,
    /// Whether the file holds a secret: see [`Config::holds_secrets`].
    secrets_in_file: bool,
}

/// The parts of a configuration that only a new start applies: where gatir
/// listens, and how much it logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixed {
    listen: Vec<SocketAddr>,
    tunnels: Vec<Tunnel>,
    socks5: Vec<SocketAddr>,
    log_level: LogLevel,
}

impl Fixed {
    /// What is different in `later`, by the name of the setting.
    pub fn differences(&self, later: &Self) -> Vec<&'static str> {
        [
            (self.listen != later.listen, "listen"),
            (self.tunnels != later.tunnels, "tunnels"),
            (self.socks5 != later.socks5, "socks5.listen"),
            (self.log_level != later.log_level, "log.level"),
        ]
        .into_iter()
        .filter_map(|(differs, name)| differs.then_some(name))
        .collect()
    }
}

/// Values that take precedence over the config file: the command-line options
/// that say the same as a setting of the file.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct Overrides {
    /// Address to listen on; repeat for several (replaces `listen` from the file)
    #[arg(long, global = true, value_name = "ADDR")]
    pub listen: Vec<SocketAddr>,

    /// PAC file or http(s) address that chooses the proxy for each request (replaces `parents` from the file)
    // Like `parents`, it is a way of finding the proxy, so it replaces the
    // other one in the file.
    #[arg(long, global = true, value_name = "FILE|URL")]
    pub pac: Option<PacLocation>,

    /// Parent proxy as HOST:PORT; repeat for several (replaces `parents` or `[pac]` from the file)
    #[arg(long = "parent", global = true, value_name = "HOST:PORT")]
    pub parents: Vec<HostPort>,

    /// A destination reached directly instead of through a proxy: a host name
    /// (with `*`/`?`), an IP address or a CIDR range; repeat for several
    /// (replaces `no_proxy` from the file)
    #[arg(long, global = true, value_name = "HOST")]
    pub no_proxy: Vec<String>,

    /// User name for the parent proxy
    #[arg(short, long, global = true)]
    pub username: Option<String>,

    /// Domain of the user
    #[arg(short, long, global = true)]
    pub domain: Option<String>,

    /// Authentication method
    #[arg(short, long, global = true, value_enum)]
    pub method: Option<AuthMethod>,

    // A password supplied interactively (`--password-prompt`), never a
    // command-line value. Replaces any password or hash from the config file.
    #[arg(skip)]
    pub password: Option<SecretString>,

    /// Forward a local port to a destination through the proxy, as in OpenSSH: `[BIND:]PORT:HOST:HOSTPORT`;
    /// repeat for several (replaces `[[tunnels]]` from the file)
    #[arg(short = 'L', long = "tunnel", global = true, value_name = "SPEC")]
    pub tunnels: Vec<Tunnel>,

    /// Address for a SOCKS5 server; repeat for several (replaces `[socks5] listen` from the file)
    #[arg(long, global = true, value_name = "ADDR")]
    pub socks5: Vec<SocketAddr>,

    /// Log verbosity (the RUST_LOG environment variable takes precedence)
    #[arg(long, global = true, value_enum)]
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
                let source = Zeroizing::new(fs::read_to_string(path).map_err(|error| {
                    ConfigError::Read {
                        path: path.to_owned(),
                        error,
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

    /// What a running server cannot change without being started again.
    pub fn fixed(&self) -> Fixed {
        Fixed {
            listen: self.listen.clone(),
            tunnels: self.tunnels.clone(),
            socks5: self
                .socks5
                .as_ref()
                .map(|socks5| socks5.listen.clone())
                .unwrap_or_default(),
            log_level: self.log_level,
        }
    }

    /// Whether the file the configuration was read from holds something a
    /// stranger must not read: a password or hash, the password of the SOCKS5
    /// server, or a header value. A password typed at the prompt is not in it.
    pub fn holds_secrets(&self) -> bool {
        self.secrets_in_file
    }
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
        let secrets_in_file = self.holds_secrets();
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

        let no_proxy_entries = if overrides.no_proxy.is_empty() {
            self.no_proxy.unwrap_or_default()
        } else {
            overrides.no_proxy
        };
        let no_proxy =
            NoProxy::new(no_proxy_entries).map_err(|err| ConfigError::invalid(err.to_string()))?;

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
            secrets_in_file,
        })
    }

    /// See [`Config::holds_secrets`].
    fn holds_secrets(&self) -> bool {
        self.credentials.as_ref().is_some_and(|credentials| {
            credentials.password.is_some()
                || credentials.nt_hash.is_some()
                || credentials.ntlmv2_hash.is_some()
        }) || self
            .socks5
            .as_ref()
            .is_some_and(socks5::RawSocks5::holds_secret)
            || self
                .headers
                .as_ref()
                .is_some_and(|headers| !headers.is_empty())
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

    use super::testing::{error_text, load};

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
            no_proxy: Vec::new(),
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
    fn command_line_no_proxy_replaces_the_file() {
        let config = Config::from_toml_str(
            r#"no_proxy = ["file.example.com"]"#,
            Overrides {
                no_proxy: vec!["cli.example.com".to_owned()],
                ..Overrides::default()
            },
        )
        .unwrap();
        assert!(config.no_proxy.matches("cli.example.com"));
        assert!(!config.no_proxy.matches("file.example.com"));

        // Without any on the command line, the file's stay.
        let config =
            Config::from_toml_str(r#"no_proxy = ["file.example.com"]"#, Overrides::default())
                .unwrap();
        assert!(config.no_proxy.matches("file.example.com"));
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
    fn only_secrets_in_the_file_count_as_held() {
        assert!(!load("").unwrap().holds_secrets());
        assert!(
            !load("[credentials]\nmethod = \"negotiate\"\n")
                .unwrap()
                .holds_secrets()
        );
        for toml in [
            "[credentials]\nusername = \"u\"\npassword = \"p\"\n",
            "[credentials]\nusername = \"u\"\nnt_hash = \"8846f7eaee8fb117ad06bdd830b7586c\"\n",
            "[socks5]\nlisten = [\"127.0.0.1:1080\"]\nusername = \"u\"\npassword = \"p\"\n",
            "[headers]\nX-Token = \"t\"\n",
        ] {
            assert!(load(toml).unwrap().holds_secrets(), "{toml}");
        }

        // A password typed at the prompt is in memory, not in the file.
        let overrides = Overrides {
            password: Some(SecretString::from("typed")),
            ..Overrides::default()
        };
        let config = Config::from_toml_str("[credentials]\nusername = \"u\"\n", overrides).unwrap();
        assert!(config.credentials.as_ref().unwrap().secret.is_some());
        assert!(!config.holds_secrets());
    }

    #[test]
    fn what_needs_a_restart_is_told_by_name() {
        let fixed = |toml: &str| load(toml).unwrap().fixed();
        let base = fixed("listen = [\"127.0.0.1:1\"]");
        assert!(
            base.differences(&fixed("listen = [\"127.0.0.1:1\"]"))
                .is_empty()
        );
        // What a reload does change is no difference.
        assert!(
            base.differences(&fixed(
                "listen = [\"127.0.0.1:1\"]\nparents = [\"p.example.com:1\"]\nno_proxy = [\"x\"]\n\
                 [access]\ndefault = \"deny\"\n[socks5]\nlisten = [\"127.0.0.1:2\"]\nusername = \"a\"\npassword = \"b\""
            ))
            .contains(&"socks5.listen")
        );
        assert_eq!(
            base.differences(&fixed("listen = [\"127.0.0.1:2\"]")),
            ["listen"]
        );
        assert_eq!(
            base.differences(&fixed(
                "listen = [\"127.0.0.1:1\"]\n[log]\nlevel = \"debug\""
            )),
            ["log.level"]
        );
        assert_eq!(
            base.differences(&fixed(
                "listen = [\"127.0.0.1:1\"]\n[[tunnels]]\nlisten = \"127.0.0.1:3\"\ntarget = \"a:22\""
            )),
            ["tunnels"]
        );
        assert!(
            base.differences(&fixed(
                "listen = [\"127.0.0.1:1\"]\nparents = [\"p.example.com:1\"]\n[access]\ndefault = \"deny\"\n\
                 [timeouts]\nconnect_secs = 3"
            ))
            .is_empty()
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
