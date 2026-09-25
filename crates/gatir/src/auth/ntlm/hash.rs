//! Password hashes (MS-NLMP sections 3.3.1 and 3.3.2).
//!
//! Both are secrets: they are enough to authenticate, so they are held in
//! `secrecy` boxes (zeroized on drop, redacted by `Debug`).

use hmac::{Hmac, KeyInit, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::{Zeroize, Zeroizing};

/// Size in bytes of both hashes.
pub const HASH_LEN: usize = 16;

struct Hash(SecretBox<[u8; HASH_LEN]>);

impl Hash {
    fn new(mut bytes: [u8; HASH_LEN]) -> Self {
        let hash = Self(SecretBox::new(Box::new(bytes)));
        bytes.zeroize();
        hash
    }

    fn expose(&self) -> &[u8; HASH_LEN] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hash([REDACTED])")
    }
}

/// The NT hash of a password: MD4 of its UTF-16LE encoding.
///
/// With the user name and domain it is enough to compute every NTLM response,
/// so it can be stored in place of the password.
#[derive(Debug)]
pub struct NtHash(Hash);

impl NtHash {
    pub fn from_password(password: &str) -> Self {
        let mut utf16 = Zeroizing::new(Vec::with_capacity(password.len() * 2));
        for unit in password.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let mut digest = [0u8; HASH_LEN];
        digest.copy_from_slice(&Md4::digest(&*utf16));
        let hash = Self(Hash::new(digest));
        digest.zeroize();
        hash
    }

    pub fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(Hash::new(bytes))
    }

    pub fn expose(&self) -> &[u8; HASH_LEN] {
        self.0.expose()
    }

    /// Lowercase hexadecimal, as written in the configuration file.
    pub fn to_hex(&self) -> String {
        hex::encode(self.expose())
    }
}

/// The NTLMv2 hash of a user (NTOWFv2): HMAC-MD5, keyed with the NT hash, of
/// the upper-cased user name followed by the domain, both UTF-16LE.
///
/// The domain is used exactly as it will be sent to the server: the server
/// derives the same key from the name it receives.
#[derive(Debug)]
pub struct Ntlmv2Hash(Hash);

impl Ntlmv2Hash {
    pub fn new(nt_hash: &NtHash, user: &str, domain: &str) -> Self {
        let mut identity = Zeroizing::new(Vec::with_capacity((user.len() + domain.len()) * 2));
        for character in user.chars() {
            for unit in upcase(character).encode_utf16(&mut [0u16; 2]) {
                identity.extend_from_slice(&unit.to_le_bytes());
            }
        }
        for unit in domain.encode_utf16() {
            identity.extend_from_slice(&unit.to_le_bytes());
        }

        let mut mac = <Hmac<Md5> as KeyInit>::new_from_slice(nt_hash.expose())
            .expect("HMAC accepts keys of any length");
        mac.update(&identity);
        let mut digest = [0u8; HASH_LEN];
        digest.copy_from_slice(&mac.finalize().into_bytes());
        let hash = Self(Hash::new(digest));
        digest.zeroize();
        hash
    }

    pub fn expose(&self) -> &[u8; HASH_LEN] {
        self.0.expose()
    }
}

/// Simple (one character to one character) upper-casing, as Windows does for
/// this purpose. Characters whose upper case is longer, like `ß`, stay as they
/// are.
fn upcase(character: char) -> char {
    let mut upper = character.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) => single,
        _ => character,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    // [MS-NLMP] v20260330, 4.2.1: User = "User", Domain = "Domain", Password = "Password".
    // NTOWFv1 is in 4.2.2.1.2 and NTOWFv2 in 4.2.4.1.1.
    #[test]
    fn nt_hash_matches_the_ms_nlmp_vector() {
        assert_eq!(
            NtHash::from_password("Password").to_hex(),
            "a4f49c406510bdcab6824ee7c30fd852"
        );
    }

    #[test]
    fn nt_hash_of_the_empty_password_is_the_md4_of_nothing() {
        assert_eq!(
            NtHash::from_password("").to_hex(),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
    }

    #[test]
    fn ntlmv2_hash_matches_the_ms_nlmp_vector() {
        let nt = NtHash::from_password("Password");
        let v2 = Ntlmv2Hash::new(&nt, "User", "Domain");
        assert_eq!(hex_of(v2.expose()), "0c868a403bfd7a93a3001ef22ef02e3f");
    }

    #[test]
    fn the_user_name_is_upper_cased_but_the_domain_is_not() {
        let nt = NtHash::from_password("Password");
        let lower_user = Ntlmv2Hash::new(&nt, "user", "Domain");
        let upper_user = Ntlmv2Hash::new(&nt, "USER", "Domain");
        assert_eq!(lower_user.expose(), upper_user.expose());

        let other_domain = Ntlmv2Hash::new(&nt, "User", "DOMAIN");
        assert_ne!(other_domain.expose(), upper_user.expose());
    }

    #[test]
    fn non_ascii_passwords_use_real_utf16() {
        // "é" is one UTF-16 unit (0x00e9), and an emoji needs a surrogate pair:
        // hashing the bytes of the UTF-8 string, or widening bytes, would differ.
        let composed = NtHash::from_password("caf\u{e9}");
        let widened_bytes = NtHash::from_password("caf\u{c3}\u{a9}");
        assert_ne!(composed.to_hex(), widened_bytes.to_hex());
        assert_eq!(NtHash::from_password("\u{1F600}").to_hex().len(), 32);
    }

    #[test]
    fn debug_output_hides_the_hash() {
        let nt = NtHash::from_password("Password");
        let v2 = Ntlmv2Hash::new(&nt, "User", "Domain");
        for text in [format!("{nt:?}"), format!("{v2:?}")] {
            assert!(text.contains("REDACTED"), "{text}");
            assert!(!text.contains("a4f49c"), "{text}");
        }
    }

    #[test]
    fn upcase_maps_one_to_one() {
        assert_eq!(upcase('a'), 'A');
        assert_eq!(upcase('\u{e9}'), '\u{c9}');
        assert_eq!(upcase('\u{df}'), '\u{df}');
        assert_eq!(upcase('7'), '7');
    }
}
