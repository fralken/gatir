//! The PAC address of the system on macOS, from the SystemConfiguration
//! framework: the "Automatic Proxy Configuration" of the network settings
//! (System Settings, Network, Proxies). The crate that wraps it has a safe
//! interface, so there is no `unsafe` here.

use system_configuration::core_foundation::number::CFNumber;
use system_configuration::core_foundation::string::CFString;
use system_configuration::dynamic_store::SCDynamicStoreBuilder;

use super::{Settings, SystemPacError};

pub(super) fn read() -> Result<Settings, SystemPacError> {
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
