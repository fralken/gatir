//! The PAC address of the user on Windows, from WinHTTP: the same
//! configuration that *Settings, Network, Proxy* shows ("Use setup script").
//!
//! This is a C interface, so this module is one of the places where `unsafe` is
//! allowed. The call fills a structure with strings that Windows allocated, and
//! every one of them is freed with `GlobalFree`.

#![allow(unsafe_code)]

use windows_sys::Win32::Foundation::GlobalFree;
use windows_sys::Win32::Networking::WinHttp::{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WinHttpGetIEProxyConfigForCurrentUser,
};

use super::{Settings, SystemPacError};

/// The longest address read, in UTF-16 units. Only a sanity bound: Windows ends
/// these strings with a zero, and reading past one that it did not end would
/// already be unsound.
const MAX_ADDRESS: usize = 64 * 1024;

pub(super) fn read() -> Result<Settings, SystemPacError> {
    let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
    // SAFETY: `config` is a structure of the kind the function fills, and lives
    // until the strings in it have been freed below.
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut config) } == 0 {
        return Err(SystemPacError::Unreadable);
    }

    let address = text(config.lpszAutoConfigUrl);
    let detect = config.fAutoDetect != 0;
    for string in [
        config.lpszAutoConfigUrl,
        config.lpszProxy,
        config.lpszProxyBypass,
    ] {
        free(string);
    }

    match address {
        Some(address) => Ok(Settings {
            enabled: true,
            address: Some(address),
        }),
        // No address, but the system looks for one by itself: not something
        // that can be followed yet, and not the same as no script.
        None if detect => Err(SystemPacError::DetectedByTheSystem),
        None => Ok(Settings {
            enabled: false,
            address: None,
        }),
    }
}

/// The text of a string that Windows returned, if there is one.
fn text(string: *mut u16) -> Option<String> {
    if string.is_null() {
        return None;
    }
    // SAFETY: Windows ends the string with a zero, so the units up to it can
    // be read. The cap does not make an unended string safe to read; it only
    // bounds what is copied.
    let units = unsafe {
        let mut length = 0;
        while length < MAX_ADDRESS && *string.add(length) != 0 {
            length += 1;
        }
        std::slice::from_raw_parts(string, length)
    };
    Some(String::from_utf16_lossy(units))
}

/// Gives back a string that Windows allocated for the caller to free.
fn free(string: *mut u16) {
    if !string.is_null() {
        // SAFETY: the string was allocated by the call above, with the
        // allocator that `GlobalFree` returns to, and is not used again.
        unsafe {
            GlobalFree(string.cast());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use super::*;

    #[test]
    fn a_string_that_is_not_there_is_no_text() {
        assert_eq!(text(null_mut()), None);
    }

    #[test]
    fn a_string_is_read_up_to_its_end() {
        let mut units: Vec<u16> = "http://pac.example.com/p.pac".encode_utf16().collect();
        units.extend([0, u16::from(b'x')]);
        assert_eq!(
            text(units.as_mut_ptr()).as_deref(),
            Some("http://pac.example.com/p.pac")
        );
        let mut empty = [0u16];
        assert_eq!(text(empty.as_mut_ptr()).as_deref(), Some(""));
    }
}
