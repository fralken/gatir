//! NTLM, as specified in MS-NLMP: the password hashes and, in later steps,
//! the messages exchanged with the proxy.

mod hash;

pub use hash::{HASH_LEN, NtHash, Ntlmv2Hash};
