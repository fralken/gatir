//! The SOCKS5 server: where it listens, and who may use it.
//!
//! Like `credentials`, this module holds a secret: the password a SOCKS5 client
//! must give. It is kept in a `secrecy` type, compared without revealing how
//! much of it was right, and never printed, not even by the errors of the
//! configuration parser.

use std::net::SocketAddr;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::ConfigError;
use super::credentials::secret_string;

/// The most a user name or a password may weigh: RFC 1929 gives each a single
/// length byte.
pub const MAX_FIELD_BYTES: usize = 255;

#[derive(Debug)]
pub struct Socks5 {
    pub listen: Vec<SocketAddr>,
    /// Who may use it. Without, anyone the access rules let in may.
    pub credentials: Option<Socks5Credentials>,
}

/// A copy is another `secrecy` box: the password stays wrapped and is wiped
/// when it is dropped.
#[derive(Debug, Clone)]
pub struct Socks5Credentials {
    pub username: String,
    password: SecretString,
}

impl Socks5Credentials {
    /// Whether these are the credentials. Both fields are always compared, and
    /// each comparison takes as long whichever byte differs, so that the time
    /// taken says nothing about how much was right. (It does say whether the
    /// lengths matched: that is not hidden.)
    pub fn verify(&self, username: &[u8], password: &[u8]) -> bool {
        let username = self.username.as_bytes().ct_eq(username);
        let password = self.password.expose_secret().as_bytes().ct_eq(password);
        (username & password).into()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSocks5 {
    listen: Option<Vec<SocketAddr>>,
    username: Option<String>,
    #[serde(default, deserialize_with = "secret_string")]
    password: Option<SecretString>,
}

impl RawSocks5 {
    pub(super) fn holds_secret(&self) -> bool {
        self.password.is_some()
    }

    /// `from_command_line` are the addresses given with `--socks5`, which
    /// replace those of the file.
    pub(super) fn resolve(self, from_command_line: Vec<SocketAddr>) -> Result<Socks5, ConfigError> {
        let listen = if from_command_line.is_empty() {
            self.listen.unwrap_or_default()
        } else {
            from_command_line
        };
        if listen.is_empty() {
            return Err(ConfigError::invalid(
                "socks5.listen must name at least one address",
            ));
        }
        let credentials = match (self.username, self.password) {
            (None, None) => None,
            (Some(username), Some(password)) => {
                for (what, len) in [
                    ("username", username.len()),
                    ("password", password.expose_secret().len()),
                ] {
                    if !(1..=MAX_FIELD_BYTES).contains(&len) {
                        return Err(ConfigError::invalid(format!(
                            "socks5.{what} must be between 1 and {MAX_FIELD_BYTES} bytes"
                        )));
                    }
                }
                Some(Socks5Credentials { username, password })
            }
            _ => {
                return Err(ConfigError::invalid(
                    "socks5.username and socks5.password go together: a client needs both",
                ));
            }
        };
        Ok(Socks5 {
            listen,
            credentials,
        })
    }
}

/// The configuration of a server that listens on `listen` and asks for nothing.
impl Socks5 {
    pub(super) fn open(listen: Vec<SocketAddr>) -> Self {
        Self {
            listen,
            credentials: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use secrecy::SecretString;

    use super::*;
    use crate::config::testing::{error_text, load};
    use crate::config::*;

    fn credentials(user: &str, password: &str) -> Socks5Credentials {
        Socks5Credentials {
            username: user.to_owned(),
            password: SecretString::from(password.to_owned()),
        }
    }

    #[test]
    fn only_the_right_pair_is_accepted() {
        let bob = credentials("bob", "s3cret");
        assert!(bob.verify(b"bob", b"s3cret"));
        for (user, password) in [
            (&b"bob"[..], &b"s3cre"[..]),
            (b"bob", b"s3cret!"),
            (b"bob", b"S3CRET"),
            (b"bo", b"s3cret"),
            (b"Bob", b"s3cret"),
            (b"alice", b"other"),
            (b"", b""),
            (b"s3cret", b"bob"),
        ] {
            assert!(!bob.verify(user, password), "{user:?} {password:?}");
        }
    }

    #[test]
    fn non_ascii_and_zero_bytes_compare_as_bytes() {
        let odd = credentials("zoë", "pässwörd");
        assert!(odd.verify("zoë".as_bytes(), "pässwörd".as_bytes()));
        assert!(!odd.verify("zoe".as_bytes(), "pässwörd".as_bytes()));
        let zeros = Socks5Credentials {
            username: "a\0b".to_owned(),
            password: SecretString::from("c\0d".to_owned()),
        };
        assert!(zeros.verify(b"a\0b", b"c\0d"));
        assert!(!zeros.verify(b"a", b"c"));
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
}
