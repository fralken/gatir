//! gatir: an authenticating HTTP proxy that logs into a corporate parent proxy
//! (NTLM, Kerberos, SSPI) on behalf of the user.

/// Crate version, as declared in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver_like() {
        assert_eq!(
            VERSION.split('.').count(),
            3,
            "unexpected version: {VERSION}"
        );
    }
}
