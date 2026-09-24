//! Identity used to authenticate to the parent proxy.
//!
//! This is one of the few modules allowed to touch secrets. Secret values are
//! held in `secrecy` types, zeroized on drop, and are never printed: neither by
//! `Debug` nor by the deserialization errors defined here.

use std::fmt;

use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};
use zeroize::Zeroize;

use super::ConfigError;

/// Length in bytes of an NT hash (MD4 digest).
pub const NT_HASH_LEN: usize = 16;

/// How gatir authenticates to the parent proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// NTLMv2 (recommended).
    #[default]
    Ntlmv2,
    /// NTLMv1 with extended session security (NTLM2 session response).
    Ntlm2sr,
    /// NTLMv1 with the NT response only.
    Nt,
    /// Kerberos/SPNEGO using the identity of the logged-in user.
    Negotiate,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ntlmv2 => "ntlmv2",
            Self::Ntlm2sr => "ntlm2sr",
            Self::Nt => "nt",
            Self::Negotiate => "negotiate",
        }
    }
}

/// The secret used to derive NTLM responses.
#[derive(Debug)]
pub enum Secret {
    Password(SecretString),
    /// NT hash. Together with the username and domain it is enough to derive
    /// every NTLM response, so the plain password need not be stored.
    NtHash(SecretBox<[u8; NT_HASH_LEN]>),
}

impl Secret {
    /// Human-readable kind, safe to print.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Password(_) => "password",
            Self::NtHash(_) => "nt_hash",
        }
    }
}

/// Validated credentials.
#[derive(Debug)]
pub struct Credentials {
    pub method: AuthMethod,
    pub username: String,
    pub domain: String,
    pub workstation: Option<String>,
    /// `None` only for [`AuthMethod::Negotiate`].
    pub secret: Option<Secret>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawCredentials {
    pub username: Option<String>,
    pub domain: Option<String>,
    pub workstation: Option<String>,
    pub method: Option<AuthMethod>,
    #[serde(default, deserialize_with = "secret_string")]
    pub password: Option<SecretString>,
    #[serde(default, deserialize_with = "secret_string")]
    pub nt_hash: Option<SecretString>,
}

impl RawCredentials {
    pub(super) fn validate(self) -> Result<Credentials, ConfigError> {
        let method = self.method.unwrap_or_default();
        let username = self.username.unwrap_or_default();
        let domain = self.domain.unwrap_or_default();

        let secret = match (self.password, self.nt_hash) {
            (Some(_), Some(_)) => {
                return Err(ConfigError::invalid(
                    "credentials.password and credentials.nt_hash are mutually exclusive",
                ));
            }
            (Some(password), None) => {
                if password.expose_secret().is_empty() {
                    return Err(ConfigError::invalid(
                        "credentials.password must not be empty",
                    ));
                }
                Some(Secret::Password(password))
            }
            (None, Some(hash)) => Some(Secret::NtHash(parse_nt_hash(&hash)?)),
            (None, None) => None,
        };

        if method == AuthMethod::Negotiate {
            if secret.is_some() {
                return Err(ConfigError::invalid(
                    "credentials.method = \"negotiate\" uses the logged-in identity; \
                     remove credentials.password / credentials.nt_hash",
                ));
            }
        } else {
            if username.trim().is_empty() {
                return Err(ConfigError::invalid(format!(
                    "credentials.username is required for method \"{}\"",
                    method.as_str()
                )));
            }
            if secret.is_none() {
                return Err(ConfigError::invalid(format!(
                    "credentials.password or credentials.nt_hash is required for method \"{}\"",
                    method.as_str()
                )));
            }
        }

        Ok(Credentials {
            method,
            username,
            domain,
            workstation: self.workstation,
            secret,
        })
    }
}

fn parse_nt_hash(hex_hash: &SecretString) -> Result<SecretBox<[u8; NT_HASH_LEN]>, ConfigError> {
    let mut bytes = [0u8; NT_HASH_LEN];
    let decoded = hex::decode_to_slice(hex_hash.expose_secret(), &mut bytes);
    let result = match decoded {
        Ok(()) => Ok(SecretBox::new(Box::new(bytes))),
        Err(_) => Err(ConfigError::invalid(
            "credentials.nt_hash must be exactly 32 hexadecimal characters",
        )),
    };
    bytes.zeroize();
    result
}

/// Deserializes a secret from a TOML string.
///
/// Non-string values are rejected without echoing them: serde's default
/// "invalid type" message would otherwise print e.g. a numeric password.
fn secret_string<'de, D>(deserializer: D) -> Result<Option<SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(SecretVisitor).map(Some)
}

/// A secret read from a TOML string, for use as a value in a table.
#[derive(Debug)]
pub(super) struct SecretValue(pub SecretString);

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(SecretVisitor).map(Self)
    }
}

struct SecretVisitor;

impl SecretVisitor {
    fn reject<E: de::Error>() -> E {
        E::custom("secret values must be quoted strings")
    }
}

impl Visitor<'_> for SecretVisitor {
    type Value = SecretString;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a quoted string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(SecretString::from(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(SecretString::from(value))
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Err(Self::reject())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Err(Self::reject())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Err(Self::reject())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(Self::reject())
    }
}
