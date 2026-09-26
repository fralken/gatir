//! NTLM, as specified in MS-NLMP: the password hashes, the messages exchanged
//! with the proxy, and the challenge responses, and the [`Authenticator`] that
//! puts them in the header fields of the exchange.

mod authenticator;
mod hash;
mod message;
mod response;

pub use authenticator::{Authenticator, challenge, header};
pub use hash::{HASH_LEN, NtHash, Ntlmv2Hash};
pub use message::{
    Challenge, Dialect, Entropy, Identity, Key, MessageError, authenticate, filetime, flags,
    negotiate,
};
pub use response::{
    CHALLENGE_LEN, LMV2_RESPONSE_LEN, Ntlmv1Responses, Ntlmv2Responses, V1_RESPONSE_LEN,
    ntlm2_session_responses, ntlmv1_responses, ntlmv2_responses,
};
