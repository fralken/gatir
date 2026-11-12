//! The PAC script that the operating system is set to use.
//!
//! On macOS it is the "Automatic Proxy Configuration" of the network settings
//! (System Settings, Network, Proxies), which gatir asks of the
//! SystemConfiguration framework. Linux has no single place for it, and Windows
//! is not supported yet: there, `[pac] system` is refused when the
//! configuration is read.

use crate::config::PacLocation;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SystemPacError {
    #[error("the system is not set to use an automatic proxy configuration (a PAC script)")]
    NotSet,
    #[error(
        "the system is set to use an automatic proxy configuration, but gives no address for it"
    )]
    NoAddress,
    #[error("the PAC address of the system cannot be used: {0}")]
    Unusable(&'static str),
    #[error("the network settings of the system cannot be read")]
    Unreadable,
    #[error("reading the PAC script of the system is not supported on this platform")]
    Unsupported,
}

/// Where the system says the PAC script is. A server takes it from the
/// operating system, and a test replaces it (see `Services`).
pub trait SystemPac: Send + Sync {
    /// The address of the script. It may be called again at every look at the
    /// script, since the settings change when a person changes them, so it
    /// answers for the moment it is called.
    fn location(&self) -> Result<PacLocation, SystemPacError>;
}

/// The settings of the operating system gatir runs on.
#[derive(Debug, Clone, Copy, Default)]
pub struct OperatingSystem;

impl SystemPac for OperatingSystem {
    fn location(&self) -> Result<PacLocation, SystemPacError> {
        let settings = read()?;
        interpret(settings.enabled, settings.address.as_deref())
    }
}

/// What the system says about its automatic proxy configuration.
struct Settings {
    enabled: bool,
    address: Option<String>,
}

/// Turns the settings into where the script is: `enabled` is whether the
/// system is set to use one, and `address` where it says to find it.
fn interpret(enabled: bool, address: Option<&str>) -> Result<PacLocation, SystemPacError> {
    if !enabled {
        return Err(SystemPacError::NotSet);
    }
    let address = address
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .ok_or(SystemPacError::NoAddress)?;
    let lower = address.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        // Anything else would be read as a file name: a script that is a file
        // is named in the configuration, and the address may hold a token, so
        // it is not repeated.
        return Err(SystemPacError::Unusable(
            "only http:// and https:// addresses can be fetched",
        ));
    }
    address.parse().map_err(|_| {
        SystemPacError::Unusable(
            "it must be http:// or https:// followed by a host, with no user name or \
             password in it",
        )
    })
}

#[cfg(target_os = "macos")]
fn read() -> Result<Settings, SystemPacError> {
    use system_configuration::core_foundation::number::CFNumber;
    use system_configuration::core_foundation::string::CFString;
    use system_configuration::dynamic_store::SCDynamicStoreBuilder;

    let store = SCDynamicStoreBuilder::new("gatir")
        .build()
        .ok_or(SystemPacError::Unreadable)?;
    // Nothing at all means that no proxy setting has been made.
    let Some(proxies) = store.get_proxies() else {
        return Ok(Settings {
            enabled: false,
            address: None,
        });
    };
    let enabled = proxies
        .find(CFString::from_static_string("ProxyAutoConfigEnable"))
        .and_then(|value| value.downcast::<CFNumber>())
        .and_then(|number| number.to_i32())
        .is_some_and(|number| number != 0);
    let address = proxies
        .find(CFString::from_static_string("ProxyAutoConfigURLString"))
        .and_then(|value| value.downcast::<CFString>())
        .map(|address| address.to_string());
    Ok(Settings { enabled, address })
}

#[cfg(not(target_os = "macos"))]
fn read() -> Result<Settings, SystemPacError> {
    Err(SystemPacError::Unsupported)
}

/// Whether this platform can say where the system's script is.
pub const fn is_supported() -> bool {
    cfg!(target_os = "macos")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_used_when_the_system_is_set_to_use_one() {
        assert_eq!(
            interpret(true, Some("http://127.0.0.1:9000/proxy.pac")),
            Ok(PacLocation::Url("http://127.0.0.1:9000/proxy.pac".into()))
        );
        assert_eq!(
            interpret(true, Some("  HTTPS://pac.example.com/p.pac?x=1 \n")),
            Ok(PacLocation::Url("HTTPS://pac.example.com/p.pac?x=1".into()))
        );
    }

    #[test]
    fn without_the_setting_or_without_an_address_there_is_nothing() {
        // An address that is left behind in the settings when the box is
        // unticked is not in use.
        assert_eq!(
            interpret(false, Some("http://pac.example.com/p.pac")),
            Err(SystemPacError::NotSet)
        );
        assert_eq!(interpret(false, None), Err(SystemPacError::NotSet));
        for address in [None, Some(""), Some("   ")] {
            assert_eq!(interpret(true, address), Err(SystemPacError::NoAddress));
        }
    }

    #[test]
    fn what_cannot_be_fetched_is_refused_without_repeating_it() {
        for address in [
            "file:///etc/proxy.pac",
            "ftp://pac.example.com/p.pac",
            "/etc/proxy.pac",
            "proxy.pac",
            "http://user:secret@pac.example.com/p.pac",
            "http:///p.pac",
        ] {
            let error = interpret(true, Some(address)).unwrap_err();
            assert!(matches!(error, SystemPacError::Unusable(_)), "{address}");
            assert!(!error.to_string().contains("secret"), "{error}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_settings_of_this_machine_can_be_read() {
        // What they say depends on the machine: only that they can be read.
        let result = OperatingSystem.location();
        assert!(
            !matches!(
                result,
                Err(SystemPacError::Unreadable | SystemPacError::Unsupported)
            ),
            "{result:?}"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_platforms_say_that_they_cannot() {
        assert!(!is_supported());
        assert_eq!(OperatingSystem.location(), Err(SystemPacError::Unsupported));
    }
}
