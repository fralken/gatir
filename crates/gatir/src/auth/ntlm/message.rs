//! The three NTLM messages (MS-NLMP 2.2.1) as far as an HTTP proxy client
//! needs them: NEGOTIATE and AUTHENTICATE are built, CHALLENGE is read.
//!
//! No session security is negotiated, so there is no signing, sealing, key
//! exchange or MIC: the session key field of AUTHENTICATE stays empty.

use std::time::{SystemTime, UNIX_EPOCH};

use super::hash::{NtHash, Ntlmv2Hash};
use super::response::{CHALLENGE_LEN, ntlm2_session_responses, ntlmv1_responses, ntlmv2_responses};
use crate::config::AuthMethod;

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

/// Which NTLM authentication to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// NTLMv2.
    V2,
    /// NTLMv1 with extended session security ("NTLM2 session response"). If
    /// the server does not offer extended session security, plain NTLMv1 is
    /// answered instead.
    V1Extended,
    /// NTLMv1, NT response only.
    V1,
}

impl Dialect {
    /// The NTLM dialect for a configured method; `None` for Negotiate/Kerberos,
    /// which does not use NTLM messages.
    pub fn from_method(method: AuthMethod) -> Option<Self> {
        match method {
            AuthMethod::Ntlmv2 => Some(Self::V2),
            AuthMethod::Ntlm2sr => Some(Self::V1Extended),
            AuthMethod::Nt => Some(Self::V1),
            AuthMethod::Negotiate => None,
        }
    }
}

/// Builds the NEGOTIATE message (type 1) that opens the exchange. The domain
/// and workstation are sent in upper case, in the OEM character set.
pub fn negotiate(dialect: Dialect, identity: &Identity<'_>) -> Result<Vec<u8>, MessageError> {
    let domain = identity.domain.to_ascii_uppercase().into_bytes();
    let workstation = identity.workstation.to_ascii_uppercase().into_bytes();

    let mut negotiated = flags::UNICODE | flags::REQUEST_TARGET | flags::NTLM | flags::ALWAYS_SIGN;
    if dialect != Dialect::V1 {
        negotiated |= flags::EXTENDED_SESSION_SECURITY | flags::KEY_128 | flags::KEY_56;
    }
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

/// Builds the AUTHENTICATE message (type 3) answering `challenge`.
pub fn authenticate(
    dialect: Dialect,
    identity: &Identity<'_>,
    nt_hash: &NtHash,
    challenge: &Challenge,
    entropy: &Entropy,
) -> Result<Vec<u8>, MessageError> {
    let mut negotiated = challenge.flags & flags::AGREED;
    let server_challenge = &challenge.server_challenge;

    let (lm, nt): (Vec<u8>, Vec<u8>) = match dialect {
        Dialect::V2 => {
            let key = Ntlmv2Hash::new(nt_hash, identity.user, identity.domain);
            // Use the server's clock when it gave one, so a skewed local
            // clock cannot make the response look stale.
            let time = challenge.timestamp().unwrap_or(entropy.time);
            let responses = ntlmv2_responses(
                &key,
                server_challenge,
                &entropy.client_nonce,
                &challenge.target_info,
                time,
            );
            (responses.lm.to_vec(), responses.nt)
        }
        Dialect::V1Extended if negotiated & flags::EXTENDED_SESSION_SECURITY != 0 => {
            let responses =
                ntlm2_session_responses(nt_hash, server_challenge, &entropy.client_nonce);
            (responses.lm.to_vec(), responses.nt.to_vec())
        }
        Dialect::V1Extended | Dialect::V1 => {
            // The flag tells the server how to read the response, so it must
            // not claim extended session security for a plain NTLMv1 one.
            negotiated &= !flags::EXTENDED_SESSION_SECURITY;
            let responses = ntlmv1_responses(nt_hash, server_challenge);
            (responses.lm.to_vec(), responses.nt.to_vec())
        }
    };

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
    let lm = place(&mut payload, AUTHENTICATE_HEADER_LEN, &lm)?;
    let nt = place(&mut payload, AUTHENTICATE_HEADER_LEN, &nt)?;
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
        let message = negotiate(Dialect::V2, &identity()).unwrap();

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
        let message = negotiate(
            Dialect::V2,
            &Identity {
                user: "u",
                domain: "",
                workstation: "",
            },
        )
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
        let message =
            authenticate(Dialect::V2, &identity(), &nt_hash, &challenge, &entropy).unwrap();

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
        let message = authenticate(
            Dialect::V2,
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
        let message = authenticate(
            Dialect::V2,
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
        let message = authenticate(
            Dialect::V2,
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
        let message = authenticate(
            Dialect::V2,
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
            authenticate(
                Dialect::V2,
                &identity(),
                &NtHash::from_password("p"),
                &challenge,
                &entropy
            ),
            Err(MessageError::TooLarge)
        );
    }

    // ---- dialects ----

    const SPEC_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    fn authenticate_with(dialect: Dialect, server_flags: u32) -> Vec<u8> {
        let challenge =
            Challenge::parse(&challenge_message(server_flags, SPEC_CHALLENGE, &[])).unwrap();
        let entropy = Entropy {
            client_nonce: [0xaa; 8],
            time: 0,
        };
        authenticate(
            dialect,
            &identity(),
            &NtHash::from_password("Password"),
            &challenge,
            &entropy,
        )
        .unwrap()
    }

    const NTLMV1_NT: &str = "67c43011f30298a2ad35ece64f16331c44bdbed927841f94";
    const NTLM2_LM: &str = "aaaaaaaaaaaaaaaa00000000000000000000000000000000";
    const NTLM2_NT: &str = "7537f803ae367128ca458204bde7caf81e97ed2683267232";

    /// [MS-NLMP] v20210625, 4.2.3.3: the CHALLENGE_MESSAGE of the NTLM2 session
    /// example. It has no target info and carries a version field.
    const SPEC_CHALLENGE_MESSAGE: &str = concat!(
        "4e544c4d53535000",         // signature
        "02000000",                 // message type
        "0c000c00",                 // target name: length, maximum length
        "38000000",                 // target name: offset
        "33820a82",                 // flags
        "0123456789abcdef",         // server challenge
        "0000000000000000",         // reserved
        "0000000000000000",         // target info: none
        "060070170000000f",         // version
        "530065007200760065007200", // target name "Server"
    );

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).unwrap()
    }

    #[test]
    fn parses_the_challenge_message_printed_in_the_specification() {
        let challenge = Challenge::parse(&unhex(SPEC_CHALLENGE_MESSAGE)).unwrap();
        assert_eq!(challenge.flags, 0x820a_8233);
        assert_eq!(challenge.server_challenge, SPEC_CHALLENGE);
        assert!(challenge.target_info.is_empty());
        assert_eq!(challenge.timestamp(), None);
    }

    #[test]
    fn answers_the_specifications_ntlm2_session_example_with_its_field_contents() {
        // 4.2.3.3 AUTHENTICATE_MESSAGE, field by field. The spec's message also
        // carries a version and a larger flag set, so only the contents of the
        // fields are compared, not the layout.
        let challenge = Challenge::parse(&unhex(SPEC_CHALLENGE_MESSAGE)).unwrap();
        let entropy = Entropy {
            client_nonce: [0xaa; 8],
            time: 0,
        };
        let identity = Identity {
            user: "User",
            domain: "Domain",
            workstation: "COMPUTER",
        };
        let message = authenticate(
            Dialect::V1Extended,
            &identity,
            &NtHash::from_password("Password"),
            &challenge,
            &entropy,
        )
        .unwrap();

        let expected = [
            (0, "aaaaaaaaaaaaaaaa00000000000000000000000000000000"), // LM
            (1, "7537f803ae367128ca458204bde7caf81e97ed2683267232"), // NT
            (2, "44006f006d00610069006e00"),                         // "Domain"
            (3, "5500730065007200"),                                 // "User"
            (4, "43004f004d0050005500540045005200"),                 // "COMPUTER"
            (5, ""),                                                 // session key
        ];
        for (index, contents) in expected {
            assert_eq!(
                hex::encode(authenticate_field(&message, index)),
                contents,
                "field {index}"
            );
        }
    }

    /// [MS-NLMP] v20210625, 4.2.4.3: the CHALLENGE_MESSAGE of the NTLMv2
    /// example, with its target info (Domain, Server and the end marker).
    const SPEC_NTLMV2_CHALLENGE_MESSAGE: &str = concat!(
        "4e544c4d53535000",                 // signature
        "02000000",                         // message type
        "0c000c00",                         // target name: length, maximum length
        "38000000",                         // target name: offset
        "33828ae2",                         // flags
        "0123456789abcdef",                 // server challenge
        "0000000000000000",                 // reserved
        "24002400",                         // target info: length, maximum length
        "44000000",                         // target info: offset
        "060070170000000f",                 // version
        "530065007200760065007200",         // target name "Server"
        "02000c0044006f006d00610069006e00", // MsvAvNbDomainName "Domain"
        "01000c00530065007200760065007200", // MsvAvNbComputerName "Server"
        "00000000",                         // MsvAvEOL
    );

    #[test]
    fn answers_the_specifications_ntlmv2_example_with_its_field_contents() {
        // 4.2.4.3 AUTHENTICATE_MESSAGE: the spec's message also has a version, a
        // MIC-era flag set and an encrypted session key, so as above only the
        // contents of the fields are compared.
        let challenge = Challenge::parse(&unhex(SPEC_NTLMV2_CHALLENGE_MESSAGE)).unwrap();
        assert_eq!(challenge.flags, 0xe28a_8233);
        assert_eq!(challenge.target_info.len(), 36);

        let entropy = Entropy {
            client_nonce: [0xaa; 8],
            time: 0,
        };
        let identity = Identity {
            user: "User",
            domain: "Domain",
            workstation: "COMPUTER",
        };
        let message = authenticate(
            Dialect::V2,
            &identity,
            &NtHash::from_password("Password"),
            &challenge,
            &entropy,
        )
        .unwrap();

        let expected = [
            (0, "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"), // LMv2
            (1, crate::auth::ntlm::response::vectors::NTLMV2_NT_RESPONSE), // NTLMv2
            (2, "44006f006d00610069006e00"),                         // "Domain"
            (3, "5500730065007200"),                                 // "User"
            (4, "43004f004d0050005500540045005200"),                 // "COMPUTER"
        ];
        for (index, contents) in expected {
            assert_eq!(
                hex::encode(authenticate_field(&message, index)),
                contents,
                "field {index}"
            );
        }
    }

    #[test]
    fn negotiate_flags_depend_on_the_dialect() {
        for (dialect, extended) in [
            (Dialect::V2, true),
            (Dialect::V1Extended, true),
            (Dialect::V1, false),
        ] {
            let message = negotiate(dialect, &identity()).unwrap();
            let negotiated = u32_at(&message, 12);
            assert_eq!(
                negotiated & flags::EXTENDED_SESSION_SECURITY != 0,
                extended,
                "{dialect:?}"
            );
            assert_ne!(negotiated & flags::UNICODE, 0);
            assert_ne!(negotiated & flags::NTLM, 0);
        }
    }

    #[test]
    fn ntlmv1_answers_with_the_nt_response_in_both_fields() {
        // The server offers extended session security, but the client did not
        // ask for it: it must not be claimed.
        let offered = flags::UNICODE | flags::NTLM | flags::EXTENDED_SESSION_SECURITY;
        let message = authenticate_with(Dialect::V1, offered);

        assert_eq!(hex::encode(authenticate_field(&message, 0)), NTLMV1_NT);
        assert_eq!(hex::encode(authenticate_field(&message, 1)), NTLMV1_NT);
        assert_eq!(u32_at(&message, 60) & flags::EXTENDED_SESSION_SECURITY, 0);
        assert!(authenticate_field(&message, 5).is_empty());
    }

    #[test]
    fn ntlm2_session_response_is_used_when_the_server_offers_it() {
        let offered = flags::UNICODE | flags::NTLM | flags::EXTENDED_SESSION_SECURITY;
        let message = authenticate_with(Dialect::V1Extended, offered);

        assert_eq!(hex::encode(authenticate_field(&message, 0)), NTLM2_LM);
        assert_eq!(hex::encode(authenticate_field(&message, 1)), NTLM2_NT);
        assert_ne!(u32_at(&message, 60) & flags::EXTENDED_SESSION_SECURITY, 0);
    }

    #[test]
    fn ntlm2_session_falls_back_to_plain_ntlmv1_when_the_server_does_not_offer_it() {
        let offered = flags::UNICODE | flags::NTLM;
        let message = authenticate_with(Dialect::V1Extended, offered);

        assert_eq!(hex::encode(authenticate_field(&message, 0)), NTLMV1_NT);
        assert_eq!(hex::encode(authenticate_field(&message, 1)), NTLMV1_NT);
        assert_eq!(u32_at(&message, 60) & flags::EXTENDED_SESSION_SECURITY, 0);
    }

    #[test]
    fn the_configured_method_selects_the_dialect() {
        assert_eq!(Dialect::from_method(AuthMethod::Ntlmv2), Some(Dialect::V2));
        assert_eq!(
            Dialect::from_method(AuthMethod::Ntlm2sr),
            Some(Dialect::V1Extended)
        );
        assert_eq!(Dialect::from_method(AuthMethod::Nt), Some(Dialect::V1));
        assert_eq!(Dialect::from_method(AuthMethod::Negotiate), None);
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
