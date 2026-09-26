//! Negotiate through the GSS-API of the operating system: Kerberos through
//! SPNEGO, with the default credentials, which are the ticket cache of the
//! logged-in user. The library is loaded when the tokens are asked for (see
//! [`api`]), so its absence costs only Negotiate.

mod api;

use std::sync::Arc;

use crate::auth::{AuthError, SecurityContext, Step, TokenSource};

/// The tokens of the system, or why its library cannot be loaded.
pub(super) fn tokens() -> Result<Arc<dyn TokenSource>, AuthError> {
    let gss = api::load().map_err(|reason| AuthError::KerberosLibrary { reason })?;
    Ok(Arc::new(Gss(gss)))
}

#[derive(Debug)]
struct Gss(&'static api::Gss);

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
        let name = api::Name::import(self.0, service, service.contains('/')).map_err(|reason| {
            AuthError::NoTicket {
                service: service.to_owned(),
                reason,
            }
        })?;
        Ok(Box::new(GssContext {
            context: api::Context::new(name),
            service: service.to_owned(),
        }))
    }
}

struct GssContext {
    context: api::Context,
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
            .step(from_parent)
            .map_err(|reason| AuthError::Exchange {
                service: self.service.clone(),
                reason,
            })?;
        Ok(Step {
            token,
            complete: self.context.is_complete(),
        })
    }
}
