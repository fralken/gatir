//! Negotiate through SSPI, the security interface of Windows: Kerberos with the
//! identity of the logged-on user when Windows can use it, and NTLM inside
//! Negotiate when it cannot (away from the domain, for instance). NTLM by
//! itself, without SPNEGO around it, is there for a parent that offers NTLM and
//! not Negotiate. No password is asked for or kept: Windows holds the
//! credentials of the session.
//!
//! This is a C interface, so this module is the one place where `unsafe` is
//! allowed. Every call says why it is sound, and every handle and buffer that
//! SSPI hands over is given back.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{SEC_E_OK, SEC_I_CONTINUE_NEEDED};
use windows_sys::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleW, DeleteSecurityContext, FreeContextBuffer, FreeCredentialsHandle,
    ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY, InitializeSecurityContextW, SECBUFFER_TOKEN,
    SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc,
};
use windows_sys::Win32::Security::Credentials::SecHandle;

use super::{describe_status, service_name};
use crate::auth::{AuthError, SecurityContext, Step, TokenSource};

pub fn tokens() -> Arc<dyn TokenSource> {
    Arc::new(Sspi)
}

#[derive(Debug)]
struct Sspi;

impl TokenSource for Sspi {
    fn start(&self, service: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
        Ok(Box::new(Context::new(service, "Negotiate")?))
    }

    /// NTLM without SPNEGO around it, with the credentials of the logged-on user.
    fn start_ntlm(&self, service: &str) -> Result<Option<Box<dyn SecurityContext>>, AuthError> {
        Ok(Some(Box::new(Context::new(service, "NTLM")?)))
    }
}

/// The security context with one service, and the credentials it is made from.
struct Context {
    credentials: SecHandle,
    /// Written by the first call that makes a token, and passed to the next.
    context: SecHandle,
    /// Whether `context` holds a context that SSPI made.
    started: bool,
    /// The service principal name, as a null-terminated wide string.
    target: Vec<u16>,
    service: String,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("service", &self.service)
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

const EMPTY: SecHandle = SecHandle {
    dwLower: 0,
    dwUpper: 0,
};

impl Context {
    /// A context of the security package named `package`, which is `Negotiate`
    /// or `NTLM`.
    fn new(service: &str, package: &str) -> Result<Self, AuthError> {
        let package = wide(package);
        let mut credentials = EMPTY;
        let mut expiry = 0i64;
        // SAFETY: `package` is a null-terminated string that lives through the
        // call; the null principal and null authentication data ask for the
        // credentials of the logged-on user; `credentials` and `expiry` are
        // valid places for the results.
        let status = unsafe {
            AcquireCredentialsHandleW(
                null(),
                package.as_ptr(),
                SECPKG_CRED_OUTBOUND,
                null(),
                null(),
                None,
                null(),
                &mut credentials,
                &mut expiry,
            )
        };
        if status != SEC_E_OK {
            return Err(AuthError::NoTicket {
                service: service.to_owned(),
                reason: describe_status(status as u32),
            });
        }
        Ok(Self {
            credentials,
            context: EMPTY,
            started: false,
            target: wide(&service_name(service)),
            service: service.to_owned(),
        })
    }
}

impl SecurityContext for Context {
    fn step(&mut self, from_parent: Option<&[u8]>) -> Result<Step, AuthError> {
        // SSPI takes the input through a non-const pointer, and does not write
        // to it: a copy costs nothing and keeps the caller's bytes out of it.
        let mut input_bytes = from_parent.map(<[u8]>::to_vec);
        let mut input = SecBuffer {
            cbBuffer: input_bytes.as_ref().map_or(0, |bytes| bytes.len() as u32),
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: input_bytes
                .as_mut()
                .map_or(null_mut(), |bytes| bytes.as_mut_ptr().cast::<c_void>()),
        };
        let input_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut input,
        };
        // SSPI allocates the token (ISC_REQ_ALLOCATE_MEMORY) and is to be asked
        // to free it.
        let mut output = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: null_mut(),
        };
        let mut output_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut output,
        };
        let mut attributes = 0u32;
        let mut expiry = 0i64;

        // The first call has no context to pass and makes one; the next calls
        // pass it, and get the same handle back. Both pointers come from one.
        let handle: *mut SecHandle = &raw mut self.context;
        let previous: *const SecHandle = if self.started { handle } else { null() };
        let input_ptr: *const SecBufferDesc = if input_bytes.is_some() {
            &raw const input_desc
        } else {
            null()
        };
        // SAFETY: the credentials are valid until `drop`; `target` is a
        // null-terminated string; `input_desc` and `output_desc` describe one
        // buffer each, which live through the call, as does `input_bytes`
        // behind the input buffer; `handle` points at a handle of this
        // context, which SSPI writes and reads.
        let status = unsafe {
            InitializeSecurityContextW(
                &raw const self.credentials,
                previous,
                self.target.as_ptr(),
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY,
                0,
                SECURITY_NATIVE_DREP,
                input_ptr,
                0,
                handle,
                &raw mut output_desc,
                &mut attributes,
                &mut expiry,
            )
        };

        // Whatever SSPI allocated is copied out and given back, whether or not
        // the call went well.
        let token = if output.pvBuffer.is_null() {
            None
        } else {
            // SAFETY: SSPI says the buffer holds `cbBuffer` bytes, and it stays
            // valid until it is freed, right after.
            let bytes = unsafe {
                std::slice::from_raw_parts(output.pvBuffer.cast::<u8>(), output.cbBuffer as usize)
            }
            .to_vec();
            // SAFETY: the buffer was allocated by SSPI, and is not used again.
            unsafe { FreeContextBuffer(output.pvBuffer) };
            (!bytes.is_empty()).then_some(bytes)
        };

        match status {
            SEC_E_OK => {
                self.started = true;
                Ok(Step {
                    token,
                    complete: true,
                })
            }
            SEC_I_CONTINUE_NEEDED => {
                self.started = true;
                Ok(Step {
                    token,
                    complete: false,
                })
            }
            error if error < 0 => Err(AuthError::NoTicket {
                service: self.service.clone(),
                reason: describe_status(error as u32),
            }),
            other => Err(AuthError::Exchange {
                service: self.service.clone(),
                reason: format!(
                    "SSPI asked for a step this program does not do (status 0x{:08X})",
                    other as u32
                ),
            }),
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: the handles were made by SSPI for this context and are not
        // used again; a context is deleted only if one was made.
        unsafe {
            if self.started {
                DeleteSecurityContext(&raw const self.context);
            }
            FreeCredentialsHandle(&raw const self.credentials);
        }
    }
}
