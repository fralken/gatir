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
use crate::noproxy::NoProxy;

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
    /// NTLMv2 hash of one user and domain: HMAC-MD5, keyed with the NT hash,
    /// of the upper-cased user name and domain. It is all NTLMv2 needs, but it
    /// cannot be used for the older methods.
    Ntlmv2Hash(SecretBox<[u8; NT_HASH_LEN]>),
}

/// A copy is another `secrecy` box: the secret stays wrapped, and is wiped when
/// it is dropped.
impl Clone for Secret {
    fn clone(&self) -> Self {
        match self {
            Self::Password(password) => {
                Self::Password(SecretString::from(password.expose_secret().to_owned()))
            }
            Self::NtHash(hash) => Self::NtHash(SecretBox::new(Box::new(*hash.expose_secret()))),
            Self::Ntlmv2Hash(hash) => {
                Self::Ntlmv2Hash(SecretBox::new(Box::new(*hash.expose_secret())))
            }
        }
    }
}

impl Secret {
    /// Whether both are the same secret of the same kind. For telling a
    /// configuration that changed from one that was read again, not for
    /// checking what a client sent.
    fn same_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Password(a), Self::Password(b)) => a.expose_secret() == b.expose_secret(),
            (Self::NtHash(a), Self::NtHash(b)) | (Self::Ntlmv2Hash(a), Self::Ntlmv2Hash(b)) => {
                a.expose_secret() == b.expose_secret()
            }
            _ => false,
        }
    }

    /// Human-readable kind, safe to print.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Password(_) => "password",
            Self::NtHash(_) => "nt_hash",
            Self::Ntlmv2Hash(_) => "ntlmv2_hash",
        }
    }
}

/// Validated credentials.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub method: AuthMethod,
    pub username: String,
    pub domain: String,
    pub workstation: Option<String>,
    /// `None` only for [`AuthMethod::Negotiate`].
    pub secret: Option<Secret>,
    /// Service name of the parent proxy, for [`AuthMethod::Negotiate`] only.
    /// `None` means `HTTP@` followed by the parent's host.
    pub spn: Option<String>,
    /// Origin servers, reached directly, that these credentials also answer an
    /// NTLM challenge from (`401`, not the parent's `407`). Empty unless
    /// configured: gatir never offers them to a server that was not named.
    pub origin_hosts: NoProxy,
}

impl Credentials {
    /// Whether these are the same credentials as `other`, secret included: what
    /// a configuration that is read again has to say for a parent to keep
    /// the connections it authenticated, and the account its record.
    pub fn same_as(&self, other: &Self) -> bool {
        let same_secret = match (&self.secret, &other.secret) {
            (None, None) => true,
            (Some(a), Some(b)) => a.same_as(b),
            _ => false,
        };
        self.method == other.method
            && self.username == other.username
            && self.domain == other.domain
            && self.workstation == other.workstation
            && self.spn == other.spn
            && self.origin_hosts.entries() == other.origin_hosts.entries()
            && same_secret
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawCredentials {
    pub username: Option<String>,
    pub domain: Option<String>,
    pub workstation: Option<String>,
    pub spn: Option<String>,
    pub method: Option<AuthMethod>,
    #[serde(default, deserialize_with = "secret_string")]
    pub password: Option<SecretString>,
    #[serde(default, deserialize_with = "secret_string")]
    pub nt_hash: Option<SecretString>,
    #[serde(default, deserialize_with = "secret_string")]
    pub ntlmv2_hash: Option<SecretString>,
    pub origin_hosts: Option<Vec<String>>,
}

impl RawCredentials {
    pub(super) fn validate(self) -> Result<Credentials, ConfigError> {
        let method = self.method.unwrap_or_default();
        let username = self.username.unwrap_or_default();
        let domain = self.domain.unwrap_or_default();

        let secret = match (self.password, self.nt_hash, self.ntlmv2_hash) {
            (None, None, None) => None,
            (Some(password), None, None) => {
                if password.expose_secret().is_empty() {
                    return Err(ConfigError::invalid(
                        "credentials.password must not be empty",
                    ));
                }
                Some(Secret::Password(password))
            }
            (None, Some(hash), None) => Some(Secret::NtHash(parse_hash("nt_hash", &hash)?)),
            (None, None, Some(hash)) => Some(Secret::Ntlmv2Hash(parse_hash("ntlmv2_hash", &hash)?)),
            _ => {
                return Err(ConfigError::invalid(
                    "credentials.password, credentials.nt_hash and credentials.ntlmv2_hash \
                     are mutually exclusive",
                ));
            }
        };

        if method == AuthMethod::Negotiate {
            if secret.is_some() {
                return Err(ConfigError::invalid(
                    "credentials.method = \"negotiate\" uses the logged-in identity; \
                     remove credentials.password, credentials.nt_hash and \
                     credentials.ntlmv2_hash",
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
                let choices = if method == AuthMethod::Ntlmv2 {
                    "credentials.password, credentials.nt_hash or credentials.ntlmv2_hash"
                } else {
                    "credentials.password or credentials.nt_hash"
                };
                return Err(ConfigError::invalid(format!(
                    "{choices} is required for method \"{}\"",
                    method.as_str()
                )));
            }
            if matches!(secret, Some(Secret::Ntlmv2Hash(_))) && method != AuthMethod::Ntlmv2 {
                return Err(ConfigError::invalid(format!(
                    "credentials.ntlmv2_hash can only be used with method \"ntlmv2\", \
                     not \"{}\"; use credentials.password or credentials.nt_hash",
                    method.as_str()
                )));
            }
        }

        let spn = match self.spn {
            None => None,
            Some(_) if method != AuthMethod::Negotiate => {
                return Err(ConfigError::invalid(
                    "credentials.spn only applies to method = \"negotiate\"",
                ));
            }
            Some(spn) if spn.trim().is_empty() => {
                return Err(ConfigError::invalid("credentials.spn must not be empty"));
            }
            Some(spn) => Some(spn.trim().to_owned()),
        };

        let origin_hosts = self.origin_hosts.unwrap_or_default();
        if !origin_hosts.is_empty() && secret.is_none() {
            return Err(ConfigError::invalid(
                "credentials.origin_hosts needs an NTLM secret (password, nt_hash or \
                 ntlmv2_hash); method = \"negotiate\" has none to answer a server's \
                 challenge with",
            ));
        }
        let origin_hosts =
            NoProxy::new(origin_hosts).map_err(|err| ConfigError::invalid(err.to_string()))?;

        Ok(Credentials {
            method,
            username,
            domain,
            workstation: self.workstation,
            secret,
            spn,
            origin_hosts,
        })
    }
}

/// Reads a 16-byte hash written as 32 hexadecimal characters. `name` is the
/// key it came from, for the error message.
fn parse_hash(
    name: &str,
    hex_hash: &SecretString,
) -> Result<SecretBox<[u8; NT_HASH_LEN]>, ConfigError> {
    let mut bytes = [0u8; NT_HASH_LEN];
    let decoded = hex::decode_to_slice(hex_hash.expose_secret(), &mut bytes);
    let result = match decoded {
        Ok(()) => Ok(SecretBox::new(Box::new(bytes))),
        Err(_) => Err(ConfigError::invalid(format!(
            "credentials.{name} must be exactly 32 hexadecimal characters"
        ))),
    };
    bytes.zeroize();
    result
}

/// Deserializes a secret from a TOML string.
///
/// Non-string values are rejected without echoing them: serde's default
/// "invalid type" message would otherwise print e.g. a numeric password.
pub(super) fn secret_string<'de, D>(deserializer: D) -> Result<Option<SecretString>, D::Error>
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
