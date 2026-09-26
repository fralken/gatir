//! Negotiate on Windows, through SSPI.
//!
//! What is only text and numbers is here, and built on every platform, so that
//! its tests run wherever the code is written. The calls to Windows are in
//! `api`.

#[cfg(windows)]
mod api;

#[cfg(windows)]
pub(super) use api::tokens;

/// The name of a service as SSPI wants it: `HTTP/host`, where the rest of gatir
/// says `HTTP@host`. A Kerberos principal (it holds a `/`) is left as it is.
#[cfg_attr(not(windows), allow(dead_code))]
fn service_name(service: &str) -> String {
    match service.split_once('@') {
        Some((class, host)) if !service.contains('/') => format!("{class}/{host}"),
        _ => service.to_owned(),
    }
}

/// An SSPI status, in words a person can act on. Windows says what went wrong
/// in a number, and the number is kept in the message, for looking it up.
#[cfg_attr(not(windows), allow(dead_code))]
fn describe_status(status: u32) -> String {
    let (name, meaning) = match status {
        0x8009_0303 => (
            "SEC_E_TARGET_UNKNOWN",
            "Windows knows no such service: check the name of the parent proxy, or set credentials.spn",
        ),
        0x8009_0322 => (
            "SEC_E_WRONG_PRINCIPAL",
            "the service is registered under another name: set credentials.spn",
        ),
        0x8009_0311 => (
            "SEC_E_NO_AUTHENTICATING_AUTHORITY",
            "no domain controller could be reached: is the computer on the corporate network or its VPN?",
        ),
        0x8009_030e => (
            "SEC_E_NO_CREDENTIALS",
            "there are no credentials: the user is not logged on with a domain identity",
        ),
        0x8009_030d => (
            "SEC_E_UNKNOWN_CREDENTIALS",
            "the credentials are not recognized",
        ),
        0x8009_030c => ("SEC_E_LOGON_DENIED", "the logon was denied"),
        0x8009_0305 => (
            "SEC_E_SECPKG_NOT_FOUND",
            "the Negotiate security package is not available",
        ),
        0x8009_0308 => (
            "SEC_E_INVALID_TOKEN",
            "the token of the parent proxy is not valid",
        ),
        _ => return format!("SSPI error 0x{status:08X}"),
    };
    format!("{meaning} ({name}, 0x{status:08X})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_is_named_for_windows_as_a_service_principal_name() {
        assert_eq!(
            service_name("HTTP@proxy.example.com"),
            "HTTP/proxy.example.com"
        );
        assert_eq!(
            service_name("HTTP/proxy.example.com@EXAMPLE.COM"),
            "HTTP/proxy.example.com@EXAMPLE.COM"
        );
        assert_eq!(
            service_name("HTTP/proxy.example.com"),
            "HTTP/proxy.example.com"
        );
        assert_eq!(service_name("plain"), "plain");
    }

    #[test]
    fn a_status_is_told_in_words_and_kept_as_a_number() {
        let text = describe_status(0x8009_0303);
        assert!(
            text.contains("SEC_E_TARGET_UNKNOWN") && text.contains("0x80090303"),
            "{text}"
        );
        assert!(text.contains("credentials.spn"), "{text}");
        assert!(describe_status(0x8009_0311).contains("domain controller"));
        assert!(describe_status(0x8009_030e).contains("no credentials"));
        assert_eq!(describe_status(0x8009_9999), "SSPI error 0x80099999");
    }
}
