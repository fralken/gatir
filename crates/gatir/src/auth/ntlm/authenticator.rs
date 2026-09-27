//! The NTLM exchange with a parent proxy, as HTTP header fields.
//!
//! NTLM authenticates a connection, not a request. The client opens with a
//! NEGOTIATE message in `Proxy-Authorization`, the proxy answers `407` with a
//! CHALLENGE in `Proxy-Authenticate`, and the client repeats the request with
//! an AUTHENTICATE message. [`Authenticator`] builds the two header values and
//! reads the challenge; sending the requests is up to the caller.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_PAD_INDIFFERENT};
use hyper::header::HeaderValue;
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use super::{
    Challenge, Dialect, Entropy, Identity, Key, NtHash, Ntlmv2Hash, authenticate, negotiate,
};
use crate::auth::{AuthError, offers};
use crate::config::{Credentials, Secret};

const SCHEME: &str = "NTLM";
/// The longest NetBIOS computer name; Windows truncates its own names to this.
const WORKSTATION_MAX: usize = 15;

/// Produces the `Proxy-Authorization` values of an NTLM exchange. One
/// instance serves every connection: it holds no per-connection state.
#[derive(Debug)]
pub struct Authenticator {
    dialect: Dialect,
    user: String,
    domain: String,
    workstation: String,
    secret: Hash,
}

/// The hash the responses are computed from.
#[derive(Debug)]
enum Hash {
    Nt(NtHash),
    Ntlmv2(Ntlmv2Hash),
}

impl Authenticator {
    pub fn new(credentials: &Credentials) -> Result<Self, AuthError> {
        let dialect = Dialect::from_method(credentials.method).ok_or(AuthError::NotNtlm)?;
        let mut domain = credentials.domain.clone();
        // The plain password is not kept: the hash is all NTLM needs.
        let secret = match &credentials.secret {
            Some(Secret::Password(password)) => {
                Hash::Nt(NtHash::from_password(password.expose_secret()))
            }
            Some(Secret::NtHash(hash)) => {
                let mut bytes = *hash.expose_secret();
                let nt_hash = NtHash::from_bytes(bytes);
                bytes.zeroize();
                Hash::Nt(nt_hash)
            }
            Some(Secret::Ntlmv2Hash(hash)) => {
                let mut bytes = *hash.expose_secret();
                let v2_hash = Ntlmv2Hash::from_bytes(bytes);
                bytes.zeroize();
                // Such a hash is made from the upper-cased user and domain,
                // and the server derives the same key from the domain it is
                // sent, so the domain must go out in upper case too.
                domain.make_ascii_uppercase();
                Hash::Ntlmv2(v2_hash)
            }
            None => return Err(AuthError::NoSecret),
        };
        Ok(Self {
            dialect,
            user: credentials.username.clone(),
            domain,
            workstation: credentials
                .workstation
                .clone()
                .unwrap_or_else(default_workstation),
            secret,
        })
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    fn identity(&self) -> Identity<'_> {
        Identity {
            user: &self.user,
            domain: &self.domain,
            workstation: &self.workstation,
        }
    }

    /// The `Proxy-Authorization` value that opens the exchange (NEGOTIATE).
    pub fn first(&self) -> Result<HeaderValue, AuthError> {
        Ok(header(&negotiate(self.dialect, &self.identity())?))
    }

    /// Answers the proxy's `407`: reads the challenge out of its
    /// `Proxy-Authenticate` fields and returns the `Proxy-Authorization`
    /// value holding the AUTHENTICATE message.
    pub fn respond<'a>(
        &self,
        fields: impl IntoIterator<Item = &'a HeaderValue>,
    ) -> Result<HeaderValue, AuthError> {
        let entropy = Entropy::fresh().map_err(AuthError::Entropy)?;
        self.respond_with(fields, &entropy)
    }

    fn respond_with<'a>(
        &self,
        fields: impl IntoIterator<Item = &'a HeaderValue>,
        entropy: &Entropy,
    ) -> Result<HeaderValue, AuthError> {
        let bytes = challenge(fields)?;
        let challenge =
            Challenge::parse(&bytes).map_err(|err| AuthError::BadChallenge(err.to_string()))?;
        let key = match &self.secret {
            Hash::Nt(hash) => Key::Nt(hash),
            Hash::Ntlmv2(hash) => Key::Ntlmv2(hash),
        };
        let message = authenticate(self.dialect, &self.identity(), key, &challenge, entropy)?;
        Ok(header(&message))
    }
}

/// The name Windows would give this machine, when none is configured.
fn default_workstation() -> String {
    let name = gethostname::gethostname().to_string_lossy().into_owned();
    let short = name.split('.').next().unwrap_or_default();
    short.chars().take(WORKSTATION_MAX).collect()
}

/// `NTLM <base64>`, marked sensitive so it never shows up in debug output.
pub fn header(message: &[u8]) -> HeaderValue {
    let mut value = HeaderValue::from_str(&format!("{SCHEME} {}", STANDARD.encode(message)))
        .expect("base64 text is a valid header value");
    value.set_sensitive(true);
    value
}

/// The NTLM challenge message that the `Proxy-Authenticate` fields carry.
pub fn challenge<'a>(
    fields: impl IntoIterator<Item = &'a HeaderValue>,
) -> Result<Vec<u8>, AuthError> {
    STANDARD_PAD_INDIFFERENT
        .decode(find_challenge(fields)?)
        .map_err(|err| AuthError::BadChallenge(err.to_string()))
}

/// The token of the NTLM challenge among the `Proxy-Authenticate` fields.
fn find_challenge<'a>(
    fields: impl IntoIterator<Item = &'a HeaderValue>,
) -> Result<&'a str, AuthError> {
    let offers = offers::all(fields);

    let mut ntlm = offers
        .iter()
        .filter(|offer| offer.scheme.eq_ignore_ascii_case(SCHEME))
        .peekable();
    if ntlm.peek().is_none() {
        return Err(AuthError::NtlmNotOffered {
            offered: offers::names(&offers),
        });
    }
    ntlm.find_map(|offer| offer.token)
        .ok_or(AuthError::NoChallenge)
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::config::AuthMethod;

    fn credentials(method: AuthMethod) -> Credentials {
        Credentials {
            method,
            username: "User".to_owned(),
            domain: "Domain".to_owned(),
            workstation: Some("Computer".to_owned()),
            secret: Some(Secret::Password(SecretString::from("Password"))),
            spn: None,
            origin_hosts: crate::noproxy::NoProxy::default(),
        }
    }

    fn authenticator() -> Authenticator {
        Authenticator::new(&credentials(AuthMethod::Ntlmv2)).unwrap()
    }

    fn fields(values: &[&str]) -> Vec<HeaderValue> {
        values
            .iter()
            .map(|value| HeaderValue::from_str(value).unwrap())
            .collect()
    }

    /// The NTLMv2 example CHALLENGE_MESSAGE of MS-NLMP 4.2.4.3.
    const SPEC_CHALLENGE_HEX: &str = concat!(
        "4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef",
        "00000000000000002400240044000000060070170000000f",
        "530065007200760065007200",
        "02000c0044006f006d00610069006e00",
        "01000c00530065007200760065007200",
        "00000000",
    );

    /// The same message as it travels in `Proxy-Authenticate`.
    fn spec_challenge() -> String {
        STANDARD.encode(hex::decode(SPEC_CHALLENGE_HEX).unwrap())
    }

    fn decoded(value: &HeaderValue) -> Vec<u8> {
        let text = value.to_str().unwrap();
        let token = text.strip_prefix("NTLM ").expect("NTLM scheme");
        STANDARD.decode(token).unwrap()
    }

    #[test]
    fn the_first_message_is_a_negotiate_message() {
        let value = authenticator().first().unwrap();
        let message = decoded(&value);
        assert_eq!(&message[..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes(message[8..12].try_into().unwrap()), 1);
    }

    #[test]
    fn answers_a_challenge_with_an_authenticate_message() {
        let challenge = fields(&[&format!("NTLM {}", spec_challenge())]);
        let value = authenticator().respond(&challenge).unwrap();
        let message = decoded(&value);
        assert_eq!(&message[..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes(message[8..12].try_into().unwrap()), 3);
    }

    #[test]
    fn matches_the_ms_nlmp_ntlmv2_example_when_the_entropy_is_fixed() {
        let entropy = Entropy {
            client_nonce: [0xaa; 8],
            time: 0,
        };
        let challenge = fields(&[&format!("NTLM {}", spec_challenge())]);
        let value = authenticator().respond_with(&challenge, &entropy).unwrap();
        let message = decoded(&value);
        // The NT response field (at 20) holds the proof of MS-NLMP 4.2.4.2.2
        // followed by the blob of 4.2.4.1.3.
        let length = usize::from(u16::from_le_bytes(message[20..22].try_into().unwrap()));
        let offset = u32::from_le_bytes(message[24..28].try_into().unwrap()) as usize;
        assert_eq!(
            hex::encode(&message[offset..offset + length]),
            concat!(
                "68cd0ab851e51c96aabc927bebef6a1c", // NT proof
                "0101000000000000",                 // versions, reserved
                "0000000000000000",                 // time
                "aaaaaaaaaaaaaaaa",                 // client nonce
                "00000000",                         // reserved
                "02000c0044006f006d00610069006e00", // MsvAvNbDomainName "Domain"
                "01000c00530065007200760065007200", // MsvAvNbComputerName "Server"
                "00000000",                         // end of the AV pairs
                "00000000",                         // trailing reserved bytes
            )
        );
    }

    #[test]
    fn the_messages_never_show_up_in_debug_output() {
        let auth = authenticator();
        let first = auth.first().unwrap();
        assert_eq!(format!("{first:?}"), "Sensitive");
        assert!(format!("{auth:?}").contains("REDACTED"));
    }

    #[test]
    fn reads_the_challenge_among_several_fields() {
        let offered = fields(&[
            "Negotiate",
            "Basic realm=\"corp, main\"",
            &format!("ntlm {}", spec_challenge()),
        ]);
        assert!(authenticator().respond(&offered).is_ok());
    }

    #[test]
    fn reads_the_challenge_when_the_schemes_share_one_field() {
        let offered = fields(&[&format!(
            "Basic realm=\"a, b\", charset=\"UTF-8\", NTLM {}, Negotiate",
            spec_challenge()
        )]);
        assert!(authenticator().respond(&offered).is_ok());
    }

    #[test]
    fn a_challenge_without_padding_is_accepted() {
        let token = spec_challenge();
        assert!(token.ends_with('='), "the test needs a padded token");
        let offered = fields(&[&format!("NTLM {}", token.trim_end_matches('='))]);
        assert!(authenticator().respond(&offered).is_ok());
    }

    #[test]
    fn says_which_schemes_the_parent_offers_when_ntlm_is_not_among_them() {
        let offered = fields(&["Basic realm=\"corp\"", "Negotiate"]);
        let error = authenticator().respond(&offered).unwrap_err();
        assert_eq!(
            error.to_string(),
            "the parent proxy does not offer NTLM authentication (it offers: Basic, Negotiate)"
        );
        let nothing = authenticator().respond(&fields(&[])).unwrap_err();
        assert_eq!(
            nothing.to_string(),
            "the parent proxy does not offer NTLM authentication"
        );
    }

    #[test]
    fn a_bare_ntlm_offer_is_not_a_challenge() {
        let error = authenticator().respond(&fields(&["NTLM"])).unwrap_err();
        assert!(matches!(error, AuthError::NoChallenge), "{error}");
    }

    #[test]
    fn rejects_challenges_that_are_not_valid() {
        for text in [
            "NTLM !!!not base64!!!",
            "NTLM AAAA",
            "NTLM TlRMTVNTUAABAAAA",
        ] {
            let error = authenticator().respond(&fields(&[text])).unwrap_err();
            assert!(
                matches!(error, AuthError::BadChallenge(_)),
                "{text}: {error}"
            );
        }
    }

    #[test]
    fn negotiate_is_not_an_ntlm_method() {
        let mut creds = credentials(AuthMethod::Negotiate);
        creds.secret = None;
        assert!(matches!(
            Authenticator::new(&creds),
            Err(AuthError::NotNtlm)
        ));
    }

    #[test]
    fn an_nt_hash_works_in_place_of_the_password() {
        let mut with_hash = credentials(AuthMethod::Ntlmv2);
        let hash = NtHash::from_password("Password");
        with_hash.secret = Some(Secret::NtHash(secrecy::SecretBox::new(Box::new(
            *hash.expose(),
        ))));

        let entropy = Entropy {
            client_nonce: [1; 8],
            time: 0,
        };
        let challenge = fields(&[&format!("NTLM {}", spec_challenge())]);
        let from_password = authenticator().respond_with(&challenge, &entropy).unwrap();
        let from_hash = Authenticator::new(&with_hash)
            .unwrap()
            .respond_with(&challenge, &entropy)
            .unwrap();
        assert_eq!(decoded(&from_password), decoded(&from_hash));
    }

    /// The NTLMv2 hash of alice / s3cret in the domain CORP, as another NTLM
    /// implementation prints it for "corp": it upper-cases the domain.
    const ALICE_HASH: &str = "dd4ee4752f859325fa0813cbfb374400";

    fn alice_with_hash(domain: &str) -> Credentials {
        let mut creds = credentials(AuthMethod::Ntlmv2);
        creds.username = "alice".to_owned();
        creds.domain = domain.to_owned();
        let bytes: [u8; 16] = hex::decode(ALICE_HASH).unwrap().try_into().unwrap();
        creds.secret = Some(Secret::Ntlmv2Hash(secrecy::SecretBox::new(Box::new(bytes))));
        creds
    }

    #[test]
    fn an_ntlmv2_hash_gives_the_response_the_password_gives() {
        let entropy = Entropy {
            client_nonce: [7; 8],
            time: 0,
        };
        let challenge = fields(&[&format!("NTLM {}", spec_challenge())]);

        let mut from_password = alice_with_hash("CORP");
        from_password.secret = Some(Secret::Password(SecretString::from("s3cret")));
        let expected = Authenticator::new(&from_password)
            .unwrap()
            .respond_with(&challenge, &entropy)
            .unwrap();

        for domain in ["CORP", "corp", "Corp"] {
            let auth = Authenticator::new(&alice_with_hash(domain)).unwrap();
            let got = auth.respond_with(&challenge, &entropy).unwrap();
            assert_eq!(decoded(&got), decoded(&expected), "domain {domain:?}");
        }
    }

    #[test]
    fn an_ntlmv2_hash_cannot_answer_the_older_dialects() {
        for method in [AuthMethod::Nt, AuthMethod::Ntlm2sr] {
            let mut creds = alice_with_hash("CORP");
            creds.method = method;
            let auth = Authenticator::new(&creds).unwrap();
            let challenge = fields(&[&format!("NTLM {}", spec_challenge())]);
            let error = auth.respond(&challenge).unwrap_err();
            assert!(matches!(error, AuthError::Message(_)), "{error}");
        }
    }

    #[test]
    fn the_default_workstation_is_a_short_name() {
        let name = default_workstation();
        assert!(name.len() <= WORKSTATION_MAX);
        assert!(!name.contains('.'));
    }
}
