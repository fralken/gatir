//! Authentication to the parent proxy.
//!
//! Together with `config`, this is where secrets are handled.

mod authenticator;
pub mod ntlm;

pub use authenticator::{AuthError, Authenticator};
