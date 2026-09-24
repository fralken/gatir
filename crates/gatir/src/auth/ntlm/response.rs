//! NTLM challenge responses (MS-NLMP 3.3): NTLMv2, and the older NTLMv1 and
//! NTLM2 session response that some proxies still require.

use des::Des;
use des::cipher::BlockCipherEncrypt;
use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use zeroize::Zeroizing;

use super::hash::{HASH_LEN, NtHash, Ntlmv2Hash};

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

/// Length of an NTLMv1 response, and of the LM field that carries it.
pub const V1_RESPONSE_LEN: usize = 24;

/// The two responses of an NTLMv1 authentication.
pub struct Ntlmv1Responses {
    pub lm: [u8; V1_RESPONSE_LEN],
    pub nt: [u8; V1_RESPONSE_LEN],
}

/// NTLMv1 with the NT response only.
///
/// The LM field repeats the NT response: no LM hash is ever computed, since
/// it is cryptographically broken (MS-NLMP: "NoLMResponseNTLMv1").
pub fn ntlmv1_responses(
    nt_hash: &NtHash,
    server_challenge: &[u8; CHALLENGE_LEN],
) -> Ntlmv1Responses {
    let nt = desl(nt_hash.expose(), server_challenge);
    Ntlmv1Responses { lm: nt, nt }
}

/// NTLMv1 with extended session security, "NTLM2 session response": the NT
/// response is over the first 8 bytes of MD5(server challenge, client nonce),
/// and the LM field holds the nonce followed by 16 zero bytes.
pub fn ntlm2_session_responses(
    nt_hash: &NtHash,
    server_challenge: &[u8; CHALLENGE_LEN],
    client_nonce: &[u8; CHALLENGE_LEN],
) -> Ntlmv1Responses {
    let mut hasher = Md5::new();
    hasher.update(server_challenge);
    hasher.update(client_nonce);
    let mut session_challenge = [0u8; CHALLENGE_LEN];
    session_challenge.copy_from_slice(&hasher.finalize()[..CHALLENGE_LEN]);

    let mut lm = [0u8; V1_RESPONSE_LEN];
    lm[..CHALLENGE_LEN].copy_from_slice(client_nonce);
    Ntlmv1Responses {
        lm,
        nt: desl(nt_hash.expose(), &session_challenge),
    }
}

/// DESL (MS-NLMP 6): DES-encrypts `data` three times, keyed with consecutive
/// 7-byte slices of the 16-byte hash padded with zeros to 21 bytes.
fn desl(hash: &[u8; HASH_LEN], data: &[u8; CHALLENGE_LEN]) -> [u8; V1_RESPONSE_LEN] {
    let mut padded = Zeroizing::new([0u8; 21]);
    padded[..HASH_LEN].copy_from_slice(hash);

    let mut response = [0u8; V1_RESPONSE_LEN];
    for part in 0..3 {
        let mut seven = [0u8; 7];
        seven.copy_from_slice(&padded[part * 7..part * 7 + 7]);
        let key = Zeroizing::new(des_key(&seven));
        let cipher = Des::new_from_slice(&*key).expect("a DES key is 8 bytes");
        let mut block = des::cipher::Block::<Des>::from(*data);
        cipher.encrypt_block(&mut block);
        response[part * CHALLENGE_LEN..(part + 1) * CHALLENGE_LEN].copy_from_slice(&block);
    }
    response
}

/// Spreads 56 key bits over 8 bytes, 7 bits each, and sets odd parity in the
/// low bit of every byte.
fn des_key(seven: &[u8; 7]) -> [u8; 8] {
    let bits = seven
        .iter()
        .fold(0u64, |all, byte| (all << 8) | u64::from(*byte));
    let mut key = [0u8; 8];
    for (index, byte) in key.iter_mut().enumerate() {
        let group = ((bits >> (49 - 7 * index)) & 0x7f) as u8;
        *byte = group << 1;
        if byte.count_ones() % 2 == 0 {
            *byte |= 1;
        }
    }
    key
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
    /// [MS-NLMP] v20210625, 4.2.4.2.2: the NTLMv2 response, an NT proof
    /// followed by the client blob (4.2.4.1.3).
    pub const NTLMV2_NT_RESPONSE: &str = concat!(
        "68cd0ab851e51c96aabc927bebef6a1c", // NT proof
        "0101000000000000",                 // versions, reserved
        "0000000000000000",                 // time
        "aaaaaaaaaaaaaaaa",                 // client nonce
        "00000000",                         // reserved
        "02000c0044006f006d00610069006e00", // MsvAvNbDomainName "Domain"
        "01000c00530065007200760065007200", // MsvAvNbComputerName "Server"
        "00000000",                         // end of the AV pairs
        "00000000",                         // trailing reserved bytes
    );

    // [MS-NLMP] v20210625, 4.2.1: User "User", Domain "Domain", Password "Password".
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
    use super::vectors::{CLIENT_NONCE, NTLMV2_NT_RESPONSE, SERVER_CHALLENGE, spec_target_info};
    use super::*;
    use crate::auth::ntlm::NtHash;

    fn spec_key() -> Ntlmv2Hash {
        Ntlmv2Hash::new(&NtHash::from_password("Password"), "User", "Domain")
    }

    /// 4.2.4.2.1.
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

    /// 4.2.4.2.2, with the temp blob of 4.2.4.1.3.
    #[test]
    fn matches_the_ms_nlmp_ntlmv2_vector() {
        let responses = ntlmv2_responses(
            &spec_key(),
            &SERVER_CHALLENGE,
            &CLIENT_NONCE,
            &spec_target_info(),
            0,
        );
        assert_eq!(hex::encode(responses.nt), NTLMV2_NT_RESPONSE);
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
    fn matches_the_ms_nlmp_ntlmv1_vector() {
        // 4.2.2.2.1: the NT response, with extended session security not set.
        let responses = ntlmv1_responses(&NtHash::from_password("Password"), &SERVER_CHALLENGE);
        assert_eq!(
            hex::encode(responses.nt),
            "67c43011f30298a2ad35ece64f16331c44bdbed927841f94"
        );
        assert_eq!(
            responses.lm, responses.nt,
            "the LM field repeats the NT response"
        );
    }

    #[test]
    fn matches_an_independent_ntlm2_session_response() {
        // 4.2.3.2.1 (LM) and 4.2.3.2.2 (NT), also reproduced on OpenSSL's DES
        // and MD5.
        let responses = ntlm2_session_responses(
            &NtHash::from_password("Password"),
            &SERVER_CHALLENGE,
            &CLIENT_NONCE,
        );
        assert_eq!(
            hex::encode(responses.lm),
            "aaaaaaaaaaaaaaaa00000000000000000000000000000000"
        );
        assert_eq!(
            hex::encode(responses.nt),
            "7537f803ae367128ca458204bde7caf81e97ed2683267232"
        );
    }

    /// Real exchanges captured from the C cntlm against a fake server whose
    /// challenge was 1122334455667788. Synthetic credentials.
    const C_CHALLENGE: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    #[test]
    fn reproduces_an_ntlmv1_response_generated_by_another_implementation() {
        let responses =
            ntlmv1_responses(&NtHash::from_password("not-a-real-password"), &C_CHALLENGE);
        assert_eq!(
            hex::encode(responses.nt),
            "834c9205d932b4879d6e135b99d1a6fafbf9ec2fc76f3b01"
        );
    }

    #[test]
    fn reproduces_an_ntlm2_session_response_generated_by_another_implementation() {
        let nonce = [0xb1, 0xa3, 0xa7, 0xa8, 0x46, 0x8e, 0x2e, 0xb0];
        let responses = ntlm2_session_responses(
            &NtHash::from_password("not-a-real-password"),
            &C_CHALLENGE,
            &nonce,
        );
        assert_eq!(
            hex::encode(responses.lm),
            "b1a3a7a8468e2eb000000000000000000000000000000000"
        );
        assert_eq!(
            hex::encode(responses.nt),
            "69f548f94884f026cf40b8d0e405ce5b683919f2684032de"
        );
    }

    #[test]
    fn des_keys_spread_56_bits_over_8_bytes_with_odd_parity() {
        assert_eq!(des_key(&[0; 7]), [0x01; 8]);
        assert_eq!(des_key(&[0xff; 7]), [0xfe; 8]);

        for seven in [
            [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde],
            [0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd],
            [0x00, 0x01, 0x80, 0x7f, 0xfe, 0x55, 0xaa],
        ] {
            let key = des_key(&seven);
            for byte in key {
                assert_eq!(byte.count_ones() % 2, 1, "{byte:#04x} has even parity");
            }
            // Dropping the parity bits gives back the 56 bits that went in.
            let packed = key
                .iter()
                .fold(0u64, |all, byte| (all << 7) | u64::from(byte >> 1));
            assert_eq!(packed.to_be_bytes()[1..], seven);
        }
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
