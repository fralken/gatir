//! Negotiate through the GSS-API of the operating system: Kerberos through
//! SPNEGO, with the default credentials, which are the ticket cache of the
//! logged-in user.

use std::sync::Arc;

// `is_complete` comes from the library's trait of the same name as ours.
use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext as _};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_SPNEGO, GSS_NT_HOSTBASED_SERVICE, GSS_NT_KRB5_PRINCIPAL};

use crate::auth::{AuthError, SecurityContext, Step, TokenSource};

pub(super) fn tokens() -> Arc<dyn TokenSource> {
    Arc::new(Gss)
}

#[derive(Debug)]
struct Gss;

impl TokenSource for Gss {
    fn token(&self, service: &str) -> Result<Vec<u8>, AuthError> {
        self.start(service)?
            .step(None)?
            .token
            .ok_or_else(|| AuthError::NoTicket {
                service: service.to_owned(),
                reason: "the system produced no token".to_owned(),
            })
    }

    fn start(&self, service: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
        let fail = |reason: String| AuthError::NoTicket {
            service: service.to_owned(),
            reason,
        };
        let kind = if service.contains('/') {
            GSS_NT_KRB5_PRINCIPAL
        } else {
            GSS_NT_HOSTBASED_SERVICE
        };
        let name =
            Name::new(service.as_bytes(), Some(kind)).map_err(|err| fail(err.to_string()))?;
        Ok(Box::new(GssContext {
            context: ClientCtx::new(None, name, CtxFlags::empty(), Some(GSS_MECH_SPNEGO)),
            service: service.to_owned(),
        }))
    }
}

struct GssContext {
    context: ClientCtx,
    service: String,
}

impl std::fmt::Debug for GssContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssContext")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

impl SecurityContext for GssContext {
    fn step(&mut self, from_parent: Option<&[u8]>) -> Result<Step, AuthError> {
        let token = self
            .context
            .step(from_parent, None)
            .map_err(|err| AuthError::Exchange {
                service: self.service.clone(),
                reason: err.to_string(),
            })?;
        Ok(Step {
            token: token.map(|token| token.to_vec()),
            complete: self.context.is_complete(),
        })
    }
}
