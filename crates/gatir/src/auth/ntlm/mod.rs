//! NTLM, as specified in MS-NLMP: the password hashes, the messages exchanged
//! with the proxy, and the challenge responses, and the [`Authenticator`] that
//! puts them in the header fields of the exchange.

mod authenticator;
mod hash;
mod message;
mod response;

pub use authenticator::{Authenticator, challenge, header, offered};
pub use hash::NtHash;
pub use message::{Challenge, MessageError};
