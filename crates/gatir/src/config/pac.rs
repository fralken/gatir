//! The `[pac]` table: where the PAC script is, and the overrides of it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use super::ConfigError;
use crate::pac::PacOverride;

/// Where a PAC script is read from.
#[derive(Clone, PartialEq, Eq)]
pub enum PacLocation {
    File(PathBuf),
    /// An `http://` or `https://` address.
    Url(String),
    /// The address that the operating system is set to use, asked again at
    /// every look at the script.
    System,
}

impl PacLocation {
    /// The address without its query and fragment, which may hold a token.
    fn shown(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Url(url) => url.split(['?', '#']).next().unwrap_or_default().to_owned(),
            Self::System => "the PAC address of the system".to_owned(),
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
        if Self::is_fetchable(&uri) {
            Ok(Self::Url(text.to_owned()))
        } else {
            Err(invalid())
        }
    }

    /// Whether gatir may fetch a script from `uri`: `http` or `https`, a host,
    /// and no user name or password. It is the rule for the address in the
    /// configuration and for every redirect that leads away from it.
    pub fn is_fetchable(uri: &hyper::Uri) -> bool {
        let scheme_ok = matches!(uri.scheme_str(), Some("http" | "https"));
        let authority_ok = uri.authority().is_some_and(|authority| {
            !authority.as_str().contains('@') && !authority.host().is_empty()
        });
        scheme_ok && authority_ok
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
            Self::System => f.write_str("System"),
        }
    }
}

/// Where the PAC script comes from, how often it is looked at, and the hosts
/// that are sent elsewhere than the script says. What the script may use (time,
/// memory, name lookups) is not configurable: see `pac::PacLimits`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacConfig {
    pub location: PacLocation,
    /// Hosts that go to the proxies named here, whatever the script answers.
    /// The first that lists a host decides.
    pub overrides: Vec<PacOverride>,
    /// How often the script is read again to see if it changed.
    pub refresh: Duration,
    /// How long to wait for a PAC script to be fetched from an address.
    pub fetch_timeout: Duration,
}

/// How long a PAC script may take to be fetched, unless `fetch_timeout_secs`
/// says otherwise.
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(15);

impl PacConfig {
    pub fn with_defaults(location: PacLocation) -> Self {
        // A file is cheap to read again, and edited by hand: look often. So is
        // the setting of the system, which changes the address when a person
        // changes it, and a script that has not changed is not fetched again.
        let refresh = match location {
            PacLocation::File(_) | PacLocation::System => Duration::from_secs(60),
            PacLocation::Url(_) => Duration::from_secs(3600),
        };
        Self {
            location,
            overrides: Vec::new(),
            refresh,
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
        }
    }

    /// Whether the script is read from the same place in the same way, so that
    /// what has been read is still good: the overrides are added to it as it is
    /// loaded, and may differ.
    pub fn same_script_as(&self, other: &Self) -> bool {
        self.location == other.location
            && self.refresh == other.refresh
            && self.fetch_timeout == other.fetch_timeout
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawPac {
    file: Option<PathBuf>,
    url: Option<String>,
    system: Option<bool>,
    refresh_secs: Option<u64>,
    fetch_timeout_secs: Option<u64>,
    #[serde(default)]
    overrides: Vec<RawOverride>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOverride {
    hosts: Vec<String>,
    proxy: String,
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
    pub(super) fn resolve(
        self,
        from_command_line: Option<PacLocation>,
        base: Option<&Path>,
    ) -> Result<PacConfig, ConfigError> {
        let system = self.system.unwrap_or(false);
        let location = match (from_command_line, self.file, self.url) {
            (Some(location), _, _) => location,
            (None, Some(_), Some(_)) => {
                return Err(ConfigError::invalid(
                    "pac.file and pac.url cannot both be set: they are two places to read the \
                     script from",
                ));
            }
            (None, Some(_), None) | (None, None, Some(_)) if system => {
                return Err(ConfigError::invalid(
                    "pac.system cannot be set with pac.file or pac.url: they are different \
                     places to read the script from",
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
            (None, None, None) if system => {
                if !crate::pac::system_pac_is_supported() {
                    return Err(ConfigError::invalid(
                        "pac.system is only supported on macOS and Windows: name the script with \
                         pac.file or pac.url",
                    ));
                }
                PacLocation::System
            }
            (None, None, None) => {
                return Err(ConfigError::invalid(
                    "pac.file, pac.url or pac.system is required in the [pac] table",
                ));
            }
        };
        let mut pac = PacConfig::with_defaults(location);
        for (index, raw) in self.overrides.iter().enumerate() {
            let one = PacOverride::new(&raw.hosts, &raw.proxy)
                .map_err(|err| ConfigError::invalid(format!("pac.overrides[{index}]: {err}")))?;
            pac.overrides.push(one);
        }
        if let Some(secs) = self.refresh_secs {
            pac.refresh = Duration::from_secs(within("refresh_secs", secs, 1, 604_800)?);
        }
        if let Some(secs) = self.fetch_timeout_secs {
            pac.fetch_timeout = Duration::from_secs(within("fetch_timeout_secs", secs, 1, 300)?);
        }
        Ok(pac)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::config::testing::{error_text, load};
    use crate::config::*;

    use super::*;

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
    fn rejects_a_pac_table_that_makes_no_sense() {
        for (toml, expected) in [
            ("[pac]", "pac.file, pac.url or pac.system is required"),
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
            ("[pac]\nfile = \"p\"\nworkers = 2", "unknown field"),
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
    fn a_pac_table_lists_overrides_in_order() {
        let config = load(
            "[pac]\nfile = \"proxy.pac\"\n\
             [[pac.overrides]]\nhosts = [\"GHCR.io\", \".githubusercontent.com\"]\n\
             proxy = \"proxy  a.example.com;direct\"\n\
             [[pac.overrides]]\nhosts = [\"*.intranet.example.com\"]\nproxy = \"DIRECT\"",
        )
        .unwrap();
        let overrides = config.pac.unwrap().overrides;
        assert_eq!(overrides.len(), 2);
        assert_eq!(overrides[0].hosts(), ["ghcr.io", "githubusercontent.com"]);
        assert_eq!(overrides[0].proxy(), "PROXY a.example.com:80; DIRECT");
        assert_eq!(overrides[1].hosts(), ["*.intranet.example.com"]);
        assert_eq!(overrides[1].proxy(), "DIRECT");
        assert!(
            load("[pac]\nfile = \"p\"")
                .unwrap()
                .pac
                .unwrap()
                .overrides
                .is_empty()
        );
    }

    #[test]
    fn rejects_overrides_that_make_no_sense() {
        let pac = "[pac]\nfile = \"p\"\n[[pac.overrides]]\n";
        for (overrides, expected) in [
            ("proxy = \"DIRECT\"", "missing field `hosts`"),
            ("hosts = [\"a.example.com\"]", "missing field `proxy`"),
            (
                "hosts = [\"a.example.com\"]\nproxy = \"DIRECT\"\nurl = \"x\"",
                "unknown field",
            ),
            (
                "hosts = []\nproxy = \"DIRECT\"",
                "pac.overrides[0]: no host was given",
            ),
            (
                "hosts = [\"http://a.example.com\"]\nproxy = \"DIRECT\"",
                "pac.overrides[0]: \"http://a.example.com\" is not a host name",
            ),
            (
                "hosts = [\"a.example.com\"]\nproxy = \"\"",
                "pac.overrides[0]: the proxy list is empty",
            ),
            (
                "hosts = [\"a.example.com\"]\nproxy = \"FTP b.example.com\"",
                "pac.overrides[0]: \"FTP b.example.com\" is not a proxy",
            ),
        ] {
            let text = error_text(&format!("{pac}{overrides}"));
            assert!(text.contains(expected), "{overrides:?} -> {text}");
        }

        // The number says which one.
        let text = error_text(&format!(
            "{pac}hosts = [\"a.example.com\"]\nproxy = \"DIRECT\"\n\
             [[pac.overrides]]\nhosts = [\"b.example.com\"]\nproxy = \"nonsense here\""
        ));
        assert!(text.contains("pac.overrides[1]"), "{text}");

        // They are overrides of a script, so there must be a script.
        let text = error_text("[[pac.overrides]]\nhosts = [\"a.example.com\"]\nproxy = \"DIRECT\"");
        assert!(
            text.contains("pac.file, pac.url or pac.system is required"),
            "{text}"
        );
    }

    #[test]
    fn a_script_named_on_the_command_line_keeps_the_overrides_of_the_file() {
        let config = Config::from_toml_str(
            "[pac]\nfile = \"file.pac\"\n[[pac.overrides]]\n\
             hosts = [\"ghcr.io\"]\nproxy = \"DIRECT\"",
            Overrides {
                pac: Some(file_location("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap();
        let pac = config.pac.unwrap();
        assert_eq!(pac.location, file_location("cli.pac"));
        assert_eq!(pac.overrides.len(), 1);
    }

    #[test]
    fn the_summary_counts_the_overrides() {
        let summary = load(
            "[pac]\nfile = \"proxy.pac\"\n[[pac.overrides]]\n\
             hosts = [\"ghcr.io\"]\nproxy = \"DIRECT\"",
        )
        .unwrap()
        .summary();
        assert!(
            summary.contains("chosen by the PAC script at proxy.pac, with 1 override\n"),
            "{summary}"
        );
    }

    #[test]
    fn the_system_script_is_chosen_with_pac_system() {
        let result = load("[pac]\nsystem = true");
        if crate::pac::system_pac_is_supported() {
            let pac = result.unwrap().pac.unwrap();
            assert_eq!(pac, PacConfig::with_defaults(PacLocation::System));
            // The setting of the system is cheap to ask again, and a person
            // changes the address: look often.
            assert_eq!(pac.refresh, Duration::from_secs(60));
            assert!(load("[pac]\nsystem = true\nrefresh_secs = 7").is_ok());
        } else {
            let text = result.unwrap_err().to_string();
            assert!(
                text.contains("pac.system is only supported on macOS and Windows"),
                "{text}"
            );
        }
    }

    #[test]
    fn the_system_script_cannot_be_chosen_with_another() {
        for table in [
            "[pac]\nsystem = true\nfile = \"p.pac\"",
            "[pac]\nsystem = true\nurl = \"http://h/p.pac\"",
        ] {
            let text = error_text(table);
            assert!(
                text.contains("pac.system cannot be set with pac.file or pac.url"),
                "{table:?} -> {text}"
            );
        }
        // Switched off, it is as if it were not there.
        assert!(load("[pac]\nsystem = false\nfile = \"p.pac\"").is_ok());
        let text = error_text("[pac]\nsystem = false");
        assert!(
            text.contains("pac.file, pac.url or pac.system is required"),
            "{text}"
        );
    }

    #[test]
    fn a_script_named_on_the_command_line_replaces_the_system_one() {
        let config = Config::from_toml_str(
            "[pac]\nsystem = true",
            Overrides {
                pac: Some(file_location("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap();
        assert_eq!(config.pac.unwrap().location, file_location("cli.pac"));
    }

    #[test]
    fn the_system_script_is_shown_without_an_address() {
        assert_eq!(
            PacLocation::System.to_string(),
            "the PAC address of the system"
        );
        assert_eq!(format!("{:?}", PacLocation::System), "System");
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

        // A script named on the command line keeps the settings of the file.
        let config = Config::from_toml_str(
            "[pac]\nfile = \"file.pac\"\nrefresh_secs = 7",
            Overrides {
                pac: Some(file_location("cli.pac")),
                ..Overrides::default()
            },
        )
        .unwrap();
        let pac = config.pac.unwrap();
        assert_eq!(
            (pac.location, pac.refresh),
            (file_location("cli.pac"), Duration::from_secs(7))
        );

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
}
