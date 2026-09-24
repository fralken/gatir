//! The three NTLM messages (MS-NLMP 2.2.1) as far as an HTTP proxy client
//! needs them: NEGOTIATE and AUTHENTICATE are built, CHALLENGE is read.
//!
//! No session security is negotiated, so there is no signing, sealing, key
//! exchange or MIC: the session key field of AUTHENTICATE stays empty.

use std::time::{SystemTime, UNIX_EPOCH};

use super::hash::{NtHash, Ntlmv2Hash};
use super::response::{CHALLENGE_LEN, ntlmv2_responses};

/// NEGOTIATE flags (MS-NLMP 2.2.2.5), the subset used here.
pub mod flags {
    pub const UNICODE: u32 = 0x0000_0001;
    pub const OEM: u32 = 0x0000_0002;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const NTLM: u32 = 0x0000_0200;
    pub const OEM_DOMAIN_SUPPLIED: u32 = 0x0000_1000;
    pub const OEM_WORKSTATION_SUPPLIED: u32 = 0x0000_2000;
    pub const ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const EXTENDED_SESSION_SECURITY: u32 = 0x0008_0000;
    pub const TARGET_INFO: u32 = 0x0080_0000;
    pub const KEY_128: u32 = 0x2000_0000;
    pub const KEY_56: u32 = 0x8000_0000;

    /// What may be echoed back in AUTHENTICATE: the server's other flags,
    /// such as signing, sealing or key exchange, are capabilities this
    /// client does not have.
    pub(super) const AGREED: u32 = UNICODE
        | OEM
        | REQUEST_TARGET
        | NTLM
        | ALWAYS_SIGN
        | EXTENDED_SESSION_SECURITY
        | TARGET_INFO
        | KEY_128
        | KEY_56;
}

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const TYPE_NEGOTIATE: u32 = 1;
const TYPE_CHALLENGE: u32 = 2;
const TYPE_AUTHENTICATE: u32 = 3;

/// Bytes before the payload of a NEGOTIATE message without a version field.
const NEGOTIATE_HEADER_LEN: usize = 32;
/// Bytes before the payload of an AUTHENTICATE message without version or MIC.
const AUTHENTICATE_HEADER_LEN: usize = 64;
/// Shortest CHALLENGE message: up to and including the reserved field.
const CHALLENGE_MIN_LEN: usize = 40;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageError {
    #[error("the NTLM challenge is too short")]
    TooShort,
    #[error("the NTLM challenge does not start with the NTLMSSP signature")]
    BadSignature,
    #[error("expected an NTLM challenge (type 2) but got message type {0}")]
    WrongType(u32),
    #[error("a field of the NTLM challenge points outside the message")]
    BadField,
    #[error("an NTLM message field is too large")]
    TooLarge,
}

/// A CHALLENGE message (type 2), as sent by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub flags: u32,
    pub server_challenge: [u8; CHALLENGE_LEN],
    /// The server's AV-pair list, unchanged; empty if it sent none.
    pub target_info: Vec<u8>,
}

impl Challenge {
    pub fn parse(message: &[u8]) -> Result<Self, MessageError> {
        if message.len() < CHALLENGE_MIN_LEN {
            return Err(MessageError::TooShort);
        }
        if &message[..8] != SIGNATURE {
            return Err(MessageError::BadSignature);
        }
        let message_type = u32_at(message, 8);
        if message_type != TYPE_CHALLENGE {
            return Err(MessageError::WrongType(message_type));
        }

        let mut server_challenge = [0u8; CHALLENGE_LEN];
        server_challenge.copy_from_slice(&message[24..32]);

        // Older servers stop after the reserved field and send no target info.
        let target_info = if message.len() >= 48 {
            field_at(message, 40)?.to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            flags: u32_at(message, 20),
            server_challenge,
            target_info,
        })
    }

    /// The server's clock (MsvAvTimestamp, a Windows FILETIME), if it sent one.
    pub fn timestamp(&self) -> Option<u64> {
        const MSV_AV_EOL: u16 = 0;
        const MSV_AV_TIMESTAMP: u16 = 7;

        let mut pairs = self.target_info.as_slice();
        while pairs.len() >= 4 {
            let id = u16::from_le_bytes([pairs[0], pairs[1]]);
            let length = usize::from(u16::from_le_bytes([pairs[2], pairs[3]]));
            let value = pairs.get(4..4 + length)?;
            match id {
                MSV_AV_EOL => return None,
                MSV_AV_TIMESTAMP if length == 8 => {
                    return Some(u64::from_le_bytes(value.try_into().ok()?));
                }
                _ => {}
            }
            pairs = &pairs[4 + length..];
        }
        None
    }
}

/// Who is authenticating.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    pub user: &'a str,
    pub domain: &'a str,
    pub workstation: &'a str,
}

/// The two inputs of a response that vary from one authentication to the
/// next, made explicit so tests can fix them.
#[derive(Debug, Clone, Copy)]
pub struct Entropy {
    pub client_nonce: [u8; CHALLENGE_LEN],
    /// Windows FILETIME: 100-nanosecond ticks since 1601-01-01 UTC.
    pub time: u64,
}

impl Entropy {
    /// A random nonce and the current time.
    pub fn fresh() -> Result<Self, getrandom::Error> {
        let mut client_nonce = [0u8; CHALLENGE_LEN];
        getrandom::fill(&mut client_nonce)?;
        Ok(Self {
            client_nonce,
            time: filetime(SystemTime::now()),
        })
    }
}

/// Converts a time to a Windows FILETIME.
pub fn filetime(time: SystemTime) -> u64 {
    const SECONDS_1601_TO_1970: u64 = 11_644_473_600;
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    (since_epoch.as_secs() + SECONDS_1601_TO_1970) * 10_000_000
        + u64::from(since_epoch.subsec_nanos() / 100)
}

/// Builds the NEGOTIATE message (type 1) that opens the exchange. The domain
/// and workstation are sent in upper case, in the OEM character set.
pub fn negotiate(identity: &Identity<'_>) -> Result<Vec<u8>, MessageError> {
    let domain = identity.domain.to_ascii_uppercase().into_bytes();
    let workstation = identity.workstation.to_ascii_uppercase().into_bytes();

    let mut negotiated = flags::UNICODE
        | flags::REQUEST_TARGET
        | flags::NTLM
        | flags::ALWAYS_SIGN
        | flags::EXTENDED_SESSION_SECURITY
        | flags::KEY_128
        | flags::KEY_56;
    if !domain.is_empty() {
        negotiated |= flags::OEM_DOMAIN_SUPPLIED;
    }
    if !workstation.is_empty() {
        negotiated |= flags::OEM_WORKSTATION_SUPPLIED;
    }

    let mut payload = Vec::new();
    let domain_field = place(&mut payload, NEGOTIATE_HEADER_LEN, &domain)?;
    let workstation_field = place(&mut payload, NEGOTIATE_HEADER_LEN, &workstation)?;

    let mut message = Vec::with_capacity(NEGOTIATE_HEADER_LEN + payload.len());
    message.extend_from_slice(SIGNATURE);
    message.extend_from_slice(&TYPE_NEGOTIATE.to_le_bytes());
    message.extend_from_slice(&negotiated.to_le_bytes());
    push_field(&mut message, domain_field);
    push_field(&mut message, workstation_field);
    message.extend_from_slice(&payload);
    Ok(message)
}

/// Builds the AUTHENTICATE message (type 3) answering `challenge` with NTLMv2.
pub fn authenticate_v2(
    identity: &Identity<'_>,
    nt_hash: &NtHash,
    challenge: &Challenge,
    entropy: &Entropy,
) -> Result<Vec<u8>, MessageError> {
    let key = Ntlmv2Hash::new(nt_hash, identity.user, identity.domain);
    // Use the server's clock when it gave one, so a skewed local clock cannot
    // make the response look stale.
    let time = challenge.timestamp().unwrap_or(entropy.time);
    let responses = ntlmv2_responses(
        &key,
        &challenge.server_challenge,
        &entropy.client_nonce,
        &challenge.target_info,
        time,
    );

    let negotiated = challenge.flags & flags::AGREED;
    let unicode = negotiated & flags::UNICODE != 0;
    let encode = |text: &str| -> Vec<u8> {
        if unicode {
            text.encode_utf16().flat_map(u16::to_le_bytes).collect()
        } else {
            text.as_bytes().to_vec()
        }
    };

    let mut payload = Vec::new();
    let domain = place(
        &mut payload,
        AUTHENTICATE_HEADER_LEN,
        &encode(identity.domain),
    )?;
    let user = place(
        &mut payload,
        AUTHENTICATE_HEADER_LEN,
        &encode(identity.user),
    )?;
    let workstation = place(
        &mut payload,
        AUTHENTICATE_HEADER_LEN,
        &encode(&identity.workstation.to_ascii_uppercase()),
    )?;
    let lm = place(&mut payload, AUTHENTICATE_HEADER_LEN, &responses.lm)?;
    let nt = place(&mut payload, AUTHENTICATE_HEADER_LEN, &responses.nt)?;
    let session_key = place(&mut payload, AUTHENTICATE_HEADER_LEN, &[])?;

    let mut message = Vec::with_capacity(AUTHENTICATE_HEADER_LEN + payload.len());
    message.extend_from_slice(SIGNATURE);
    message.extend_from_slice(&TYPE_AUTHENTICATE.to_le_bytes());
    for field in [lm, nt, domain, user, workstation, session_key] {
        push_field(&mut message, field);
    }
    message.extend_from_slice(&negotiated.to_le_bytes());
    message.extend_from_slice(&payload);
    Ok(message)
}

/// A security buffer descriptor: length and offset from the message start.
#[derive(Clone, Copy)]
struct Field {
    length: u16,
    offset: u32,
}

/// Appends `bytes` to `payload` and describes where they will sit in a message
/// whose header is `header_len` bytes long.
fn place(payload: &mut Vec<u8>, header_len: usize, bytes: &[u8]) -> Result<Field, MessageError> {
    let length = u16::try_from(bytes.len()).map_err(|_| MessageError::TooLarge)?;
    let offset = u32::try_from(header_len + payload.len()).map_err(|_| MessageError::TooLarge)?;
    payload.extend_from_slice(bytes);
    Ok(Field { length, offset })
}

/// Writes a field descriptor: length, the same as maximum length, offset.
fn push_field(message: &mut Vec<u8>, field: Field) {
    message.extend_from_slice(&field.length.to_le_bytes());
    message.extend_from_slice(&field.length.to_le_bytes());
    message.extend_from_slice(&field.offset.to_le_bytes());
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// The bytes a field descriptor at `position` points to.
fn field_at(message: &[u8], position: usize) -> Result<&[u8], MessageError> {
    let length = usize::from(u16::from_le_bytes([
        message[position],
        message[position + 1],
    ]));
    let offset = u32_at(message, position + 4) as usize;
    let end = offset.checked_add(length).ok_or(MessageError::BadField)?;
    message.get(offset..end).ok_or(MessageError::BadField)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CHALLENGE message as a server would send it.
    fn challenge_message(flags: u32, server_challenge: [u8; 8], target_info: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(SIGNATURE);
        message.extend_from_slice(&TYPE_CHALLENGE.to_le_bytes());
        message.extend_from_slice(&[0; 8]); // target name: empty
        message.extend_from_slice(&flags.to_le_bytes());
        message.extend_from_slice(&server_challenge);
        message.extend_from_slice(&[0; 8]); // reserved
        message.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        message.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        message.extend_from_slice(&48u32.to_le_bytes());
        message.extend_from_slice(target_info);
        message
    }

    fn av_pair(id: u16, value: &[u8]) -> Vec<u8> {
        let mut pair = id.to_le_bytes().to_vec();
        pair.extend_from_slice(&(value.len() as u16).to_le_bytes());
        pair.extend_from_slice(value);
        pair
    }

    fn identity() -> Identity<'static> {
        Identity {
            user: "User",
            domain: "Domain",
            workstation: "Computer",
        }
    }

    /// Reads a field of an AUTHENTICATE message back out.
    fn authenticate_field(message: &[u8], index: usize) -> &[u8] {
        field_at(message, 12 + 8 * index).unwrap()
    }

    // ---- CHALLENGE ----

    #[test]
    fn parses_a_challenge_with_target_info() {
        let info = av_pair(2, b"D\0O\0");
        let message = challenge_message(0xe288_8235, [1, 2, 3, 4, 5, 6, 7, 8], &info);
        let challenge = Challenge::parse(&message).unwrap();

        assert_eq!(challenge.flags, 0xe288_8235);
        assert_eq!(challenge.server_challenge, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(challenge.target_info, info);
    }

    #[test]
    fn parses_a_challenge_without_target_info() {
        // Older servers end the message after the reserved field.
        let mut message = challenge_message(0x0000_8201, [9; 8], &[]);
        message.truncate(CHALLENGE_MIN_LEN);
        let challenge = Challenge::parse(&message).unwrap();
        assert!(challenge.target_info.is_empty());
        assert_eq!(challenge.server_challenge, [9; 8]);
    }

    #[test]
    fn rejects_malformed_challenges() {
        let good = challenge_message(1, [0; 8], &av_pair(2, b"ab"));

        assert_eq!(Challenge::parse(&[]), Err(MessageError::TooShort));
        assert_eq!(Challenge::parse(&good[..39]), Err(MessageError::TooShort));

        let mut bad_signature = good.clone();
        bad_signature[0] = b'X';
        assert_eq!(
            Challenge::parse(&bad_signature),
            Err(MessageError::BadSignature)
        );

        let mut wrong_type = good.clone();
        wrong_type[8] = 3;
        assert_eq!(
            Challenge::parse(&wrong_type),
            Err(MessageError::WrongType(3))
        );

        // The target info field points past the end of the message.
        let mut overflowing = good.clone();
        overflowing[44..48].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert_eq!(Challenge::parse(&overflowing), Err(MessageError::BadField));
        let mut too_long = good;
        too_long[40..42].copy_from_slice(&500u16.to_le_bytes());
        assert_eq!(Challenge::parse(&too_long), Err(MessageError::BadField));
    }

    #[test]
    fn finds_the_server_timestamp() {
        let mut info = av_pair(2, b"D\0");
        info.extend(av_pair(7, &0x0102_0304_0506_0708u64.to_le_bytes()));
        info.extend(av_pair(0, &[]));
        let challenge = Challenge::parse(&challenge_message(1, [0; 8], &info)).unwrap();
        assert_eq!(challenge.timestamp(), Some(0x0102_0304_0506_0708));
    }

    #[test]
    fn timestamp_is_absent_or_ignored_when_it_cannot_be_trusted() {
        let cases: [Vec<u8>; 4] = [
            vec![],
            av_pair(2, b"D\0"),
            // EOL before the timestamp: what follows is not part of the list
            [av_pair(0, &[]), av_pair(7, &[1; 8])].concat(),
            // wrong length for a timestamp
            av_pair(7, &[1; 4]),
        ];
        for info in cases {
            let challenge = Challenge {
                flags: 0,
                server_challenge: [0; 8],
                target_info: info.clone(),
            };
            assert_eq!(challenge.timestamp(), None, "{info:?}");
        }
        // A truncated pair must not panic.
        let truncated = Challenge {
            flags: 0,
            server_challenge: [0; 8],
            target_info: vec![7, 0, 200, 0, 1, 2],
        };
        assert_eq!(truncated.timestamp(), None);
    }

    #[test]
    fn parsing_never_panics_on_arbitrary_or_corrupted_input() {
        // Deterministic pseudo-random bytes, so a failure is reproducible.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        let valid = challenge_message(
            0xa089_8205,
            [1; 8],
            &[av_pair(2, b"D\0O\0"), av_pair(7, &[9; 8]), av_pair(0, &[])].concat(),
        );
        for round in 0..20_000 {
            let candidate: Vec<u8> = if round % 2 == 0 {
                // random bytes of a random length
                (0..next() % 120).map(|_| next() as u8).collect()
            } else {
                // a valid message with a few bytes overwritten and maybe cut short
                let mut bytes = valid.clone();
                for _ in 0..=next() % 4 {
                    let position = (next() as usize) % bytes.len();
                    bytes[position] = next() as u8;
                }
                bytes.truncate((next() as usize) % (bytes.len() + 1));
                bytes
            };
            if let Ok(challenge) = Challenge::parse(&candidate) {
                let _ = challenge.timestamp();
            }
        }
    }

    // ---- NEGOTIATE ----

    #[test]
    fn negotiate_carries_flags_domain_and_workstation() {
        let message = negotiate(&identity()).unwrap();

        assert_eq!(&message[..8], b"NTLMSSP\0");
        assert_eq!(u32_at(&message, 8), 1);
        let negotiated = u32_at(&message, 12);
        for flag in [
            flags::UNICODE,
            flags::NTLM,
            flags::EXTENDED_SESSION_SECURITY,
            flags::OEM_DOMAIN_SUPPLIED,
            flags::OEM_WORKSTATION_SUPPLIED,
        ] {
            assert_ne!(negotiated & flag, 0, "flag {flag:#x} missing");
        }
        assert_eq!(field_at(&message, 16).unwrap(), b"DOMAIN");
        assert_eq!(field_at(&message, 24).unwrap(), b"COMPUTER");
    }

    #[test]
    fn negotiate_without_domain_or_workstation_omits_their_flags() {
        let message = negotiate(&Identity {
            user: "u",
            domain: "",
            workstation: "",
        })
        .unwrap();
        let negotiated = u32_at(&message, 12);
        assert_eq!(negotiated & flags::OEM_DOMAIN_SUPPLIED, 0);
        assert_eq!(negotiated & flags::OEM_WORKSTATION_SUPPLIED, 0);
        assert_eq!(message.len(), NEGOTIATE_HEADER_LEN);
    }

    // ---- AUTHENTICATE ----

    #[test]
    fn authenticate_v2_places_every_field() {
        let info = crate::auth::ntlm::response::vectors::spec_target_info();
        let challenge = Challenge::parse(&challenge_message(
            flags::UNICODE | flags::NTLM | flags::EXTENDED_SESSION_SECURITY,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            &info,
        ))
        .unwrap();
        let entropy = Entropy {
            client_nonce: [0xaa; 8],
            time: 0,
        };
        let nt_hash = NtHash::from_password("Password");
        let message = authenticate_v2(&identity(), &nt_hash, &challenge, &entropy).unwrap();

        assert_eq!(&message[..8], b"NTLMSSP\0");
        assert_eq!(u32_at(&message, 8), 3);
        // Fields, in header order: LM, NT, domain, user, workstation, session key.
        assert_eq!(
            hex::encode(authenticate_field(&message, 0)),
            "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"
        );
        assert!(
            authenticate_field(&message, 1)
                .starts_with(&[0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96])
        );
        assert_eq!(
            authenticate_field(&message, 2),
            "Domain"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
        );
        assert_eq!(
            authenticate_field(&message, 3),
            "User"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
        );
        assert_eq!(
            authenticate_field(&message, 4),
            "COMPUTER"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
        );
        assert!(authenticate_field(&message, 5).is_empty());
    }

    #[test]
    fn authenticate_echoes_only_the_flags_this_client_supports() {
        // The server offers signing, sealing and key exchange; we cannot do them.
        let offered = flags::UNICODE | flags::NTLM | 0x10 | 0x20 | 0x4000_0000 | 0x0200_0000;
        let challenge = Challenge::parse(&challenge_message(offered, [0; 8], &[])).unwrap();
        let entropy = Entropy {
            client_nonce: [0; 8],
            time: 0,
        };
        let message = authenticate_v2(
            &identity(),
            &NtHash::from_password("p"),
            &challenge,
            &entropy,
        )
        .unwrap();

        let echoed = u32_at(&message, 60);
        assert_eq!(echoed, flags::UNICODE | flags::NTLM);
    }

    #[test]
    fn the_server_clock_wins_over_the_local_one() {
        let info = [av_pair(7, &42u64.to_le_bytes()), av_pair(0, &[])].concat();
        let challenge =
            Challenge::parse(&challenge_message(flags::UNICODE, [3; 8], &info)).unwrap();
        let entropy = Entropy {
            client_nonce: [7; 8],
            time: 999,
        };
        let message = authenticate_v2(
            &identity(),
            &NtHash::from_password("p"),
            &challenge,
            &entropy,
        )
        .unwrap();

        let nt = authenticate_field(&message, 1);
        // proof (16) + version bytes and reserved (8), then the time
        assert_eq!(&nt[24..32], &42u64.to_le_bytes());
    }

    #[test]
    fn without_a_server_clock_the_local_time_is_used() {
        let challenge = Challenge::parse(&challenge_message(flags::UNICODE, [3; 8], &[])).unwrap();
        let entropy = Entropy {
            client_nonce: [7; 8],
            time: 999,
        };
        let message = authenticate_v2(
            &identity(),
            &NtHash::from_password("p"),
            &challenge,
            &entropy,
        )
        .unwrap();
        assert_eq!(
            &authenticate_field(&message, 1)[24..32],
            &999u64.to_le_bytes()
        );
    }

    #[test]
    fn strings_use_the_oem_set_when_the_server_does_not_offer_unicode() {
        let challenge =
            Challenge::parse(&challenge_message(flags::OEM | flags::NTLM, [0; 8], &[])).unwrap();
        let entropy = Entropy {
            client_nonce: [0; 8],
            time: 0,
        };
        let message = authenticate_v2(
            &identity(),
            &NtHash::from_password("p"),
            &challenge,
            &entropy,
        )
        .unwrap();
        assert_eq!(authenticate_field(&message, 3), b"User");
        assert_eq!(authenticate_field(&message, 2), b"Domain");
    }

    #[test]
    fn oversized_target_info_is_refused_instead_of_truncated() {
        let challenge = Challenge {
            flags: flags::UNICODE,
            server_challenge: [0; 8],
            target_info: vec![0; 70_000],
        };
        let entropy = Entropy {
            client_nonce: [0; 8],
            time: 0,
        };
        assert_eq!(
            authenticate_v2(
                &identity(),
                &NtHash::from_password("p"),
                &challenge,
                &entropy
            ),
            Err(MessageError::TooLarge)
        );
    }

    #[test]
    fn filetime_counts_from_1601() {
        assert_eq!(filetime(UNIX_EPOCH), 116_444_736_000_000_000);
        let one_second_later = UNIX_EPOCH + std::time::Duration::from_secs(1);
        assert_eq!(filetime(one_second_later), 116_444_736_010_000_000);
    }

    #[test]
    fn fresh_entropy_differs_each_time() {
        let first = Entropy::fresh().unwrap();
        let second = Entropy::fresh().unwrap();
        assert_ne!(first.client_nonce, second.client_nonce);
        assert!(first.time > 116_444_736_000_000_000);
    }
}
