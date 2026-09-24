//! NTLMv2 challenge responses (MS-NLMP 3.3.2 and 2.2.2.7).

use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;

use super::hash::Ntlmv2Hash;

/// Length of the server challenge and of the client nonce.
pub const CHALLENGE_LEN: usize = 8;
/// Length of the LMv2 response: an HMAC-MD5 and the client nonce.
pub const LMV2_RESPONSE_LEN: usize = 16 + CHALLENGE_LEN;

/// The two responses of an NTLMv2 authentication.
pub struct Ntlmv2Responses {
    /// HMAC-MD5 over both challenges, followed by the client nonce.
    pub lm: [u8; LMV2_RESPONSE_LEN],
    /// The NT proof (HMAC-MD5 over the server challenge and the client
    /// blob), followed by the client blob itself.
    pub nt: Vec<u8>,
}

/// Computes the responses.
///
/// `target_info` is the server's AV-pair list from its CHALLENGE message,
/// copied unchanged into the client blob. `time` is a Windows FILETIME.
pub fn ntlmv2_responses(
    key: &Ntlmv2Hash,
    server_challenge: &[u8; CHALLENGE_LEN],
    client_nonce: &[u8; CHALLENGE_LEN],
    target_info: &[u8],
    time: u64,
) -> Ntlmv2Responses {
    // NTLMv2_CLIENT_CHALLENGE: versions, reserved bytes, time, nonce, reserved
    // bytes, the server's AV pairs, and four more reserved bytes.
    let mut blob = Vec::with_capacity(32 + target_info.len());
    blob.extend_from_slice(&[0x01, 0x01, 0, 0, 0, 0, 0, 0]);
    blob.extend_from_slice(&time.to_le_bytes());
    blob.extend_from_slice(client_nonce);
    blob.extend_from_slice(&[0; 4]);
    blob.extend_from_slice(target_info);
    blob.extend_from_slice(&[0; 4]);

    let proof = hmac_md5(key, &[server_challenge, &blob]);
    let mut nt = Vec::with_capacity(16 + blob.len());
    nt.extend_from_slice(&proof);
    nt.extend_from_slice(&blob);

    let lm_proof = hmac_md5(key, &[server_challenge, client_nonce]);
    let mut lm = [0u8; LMV2_RESPONSE_LEN];
    lm[..16].copy_from_slice(&lm_proof);
    lm[16..].copy_from_slice(client_nonce);

    Ntlmv2Responses { lm, nt }
}

fn hmac_md5(key: &Ntlmv2Hash, parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Hmac<Md5> as KeyInit>::new_from_slice(key.expose())
        .expect("HMAC accepts keys of any length");
    for part in parts {
        mac.update(part);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// The MS-NLMP section 4.2 test inputs, shared with the message tests.
#[cfg(test)]
pub(super) mod vectors {
    // User "User", Domain "Domain", Password "Password".
    pub const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    pub const CLIENT_NONCE: [u8; 8] = [0xaa; 8];

    /// The spec's ServerName: MsvAvNbDomainName "Domain", MsvAvNbComputerName
    /// "Server", then the end-of-list pair.
    pub fn spec_target_info() -> Vec<u8> {
        let mut info = Vec::new();
        for (id, text) in [(2u16, "Domain"), (1, "Server")] {
            let value: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            info.extend_from_slice(&id.to_le_bytes());
            info.extend_from_slice(&(value.len() as u16).to_le_bytes());
            info.extend_from_slice(&value);
        }
        info.extend_from_slice(&[0; 4]);
        info
    }
}

#[cfg(test)]
mod tests {
    use super::vectors::{CLIENT_NONCE, SERVER_CHALLENGE, spec_target_info};
    use super::*;
    use crate::auth::ntlm::NtHash;

    fn spec_key() -> Ntlmv2Hash {
        Ntlmv2Hash::new(&NtHash::from_password("Password"), "User", "Domain")
    }

    #[test]
    fn matches_the_ms_nlmp_lmv2_vector() {
        let responses = ntlmv2_responses(
            &spec_key(),
            &SERVER_CHALLENGE,
            &CLIENT_NONCE,
            &spec_target_info(),
            0,
        );
        assert_eq!(
            hex::encode(responses.lm),
            "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn matches_the_ms_nlmp_ntlmv2_vector() {
        let responses = ntlmv2_responses(
            &spec_key(),
            &SERVER_CHALLENGE,
            &CLIENT_NONCE,
            &spec_target_info(),
            0,
        );
        assert_eq!(
            hex::encode(responses.nt),
            "68cd0ab851e51c96aabc927bebef6a1c\
             01010000000000000000000000000000aaaaaaaaaaaaaaaa00000000\
             02000c0044006f006d00610069006e00\
             01000c00530065007200760065007200\
             00000000\
             00000000"
        );
    }

    /// A real exchange: the responses the C cntlm sent to a fake server with
    /// this challenge and target info. Synthetic credentials.
    #[test]
    fn reproduces_a_response_generated_by_another_implementation() {
        let key = Ntlmv2Hash::new(
            &NtHash::from_password("not-a-real-password"),
            "testuser",
            "TESTDOM",
        );
        let challenge: [u8; 8] = hex::decode("1122334455667788").unwrap().try_into().unwrap();
        let nonce: [u8; 8] = hex::decode("49f98e2c578506d1").unwrap().try_into().unwrap();
        let target_info = hex::decode(
            "02000e00540045005300540044004f004d0001001200500052004f005800590048004f005300540004002600740065007300740064006f006d002e006500780061006d0070006c0065002e0063006f006d0003003a00700072006f007800790068006f00730074002e00740065007300740064006f006d002e006500780061006d0070006c0065002e0063006f006d0000000000",
        )
        .unwrap();

        let responses =
            ntlmv2_responses(&key, &challenge, &nonce, &target_info, 134347403850000000);

        assert_eq!(
            hex::encode(responses.lm),
            "2213153faea36ac0357d2e8d2dfef9e049f98e2c578506d1"
        );
        assert_eq!(
            hex::encode(responses.nt),
            "ec5758338aafa101f250608ed516db1f010100000000000080a6f982404cdd0149f98e2c578506d10000000002000e00540045005300540044004f004d0001001200500052004f005800590048004f005300540004002600740065007300740064006f006d002e006500780061006d0070006c0065002e0063006f006d0003003a00700072006f007800790068006f00730074002e00740065007300740064006f006d002e006500780061006d0070006c0065002e0063006f006d000000000000000000"
        );
    }

    #[test]
    fn the_time_and_nonce_end_up_in_the_blob() {
        let responses = ntlmv2_responses(
            &spec_key(),
            &SERVER_CHALLENGE,
            &[0x11; 8],
            &[0, 0, 0, 0],
            0x0102_0304_0506_0708,
        );
        let blob = &responses.nt[16..];
        assert_eq!(&blob[8..16], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&blob[16..24], &[0x11; 8]);
        assert_eq!(blob.len(), 32 + 4);
    }
}
