//! The GSS-API of the operating system (RFC 2743, and RFC 2744 for its C
//! bindings), loaded when it is first needed.
//!
//! The library is opened at run time, and not linked, so that gatir starts and
//! serves NTLM on a computer that has no Kerberos library: only Negotiate needs
//! it. That is also why there is no binding to generate at build time. Only the
//! few functions that an initiator of a security context uses are declared,
//! with the types the specification gives them.
//!
//! This is a C interface, so this module is one of the places where `unsafe` is
//! allowed. Every call says why it is sound, and every buffer, name and context
//! that the library hands over is given back.

#![allow(unsafe_code)]

use std::ffi::{c_int, c_void};
use std::ptr::null_mut;
use std::sync::OnceLock;

use libloading::Library;

/// `OM_uint32`: the type of every status, flag and time.
type Status = u32;
/// What `gss_name_t` and `gss_ctx_id_t` are: a pointer to what the library keeps.
type Handle = *mut c_void;

/// `gss_buffer_desc`.
#[repr(C)]
struct Buffer {
    length: usize,
    value: *mut c_void,
}

impl Buffer {
    const EMPTY: Self = Self {
        length: 0,
        value: null_mut(),
    };

    /// A buffer over `bytes`, for the library to read: the specification gives
    /// it a non-const pointer, and the library does not write to what it reads.
    fn over(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len(),
            value: bytes.as_ptr().cast_mut().cast(),
        }
    }
}

/// `gss_OID_desc`: the contents of a DER object identifier, without its tag and
/// length.
#[repr(C)]
struct Oid {
    length: Status,
    elements: *mut c_void,
}

// SAFETY: `elements` only ever points at bytes this crate owns as `'static`
// data (see `Oid::of`'s callers) or at the loaded library's own global data
// (macOS, see `Gss::resolve`), read-only either way, so sharing an `Oid` (or a
// pointer to one) across threads is sound; needed for the `static`s below.
unsafe impl Sync for Oid {}

#[cfg(not(target_os = "macos"))]
impl Oid {
    const fn of(bytes: &'static [u8]) -> Self {
        Self {
            length: bytes.len() as Status,
            elements: bytes.as_ptr().cast_mut().cast(),
        }
    }
}

// On macOS, the well-known OIDs below are read from the library itself
// instead (see `resolve()`): its GSS-API, for at least the host-based-service
// and Kerberos-principal-name name types and the SPNEGO mechanism, appears to
// compare the *pointer* it is given against its own copies of these for some
// of what it does, not only their bytes, and one of our own, at a different
// address, however byte-identical, took a path that corrupted memory (found
// by comparing against another proxy's own working equivalent of this call,
// which passes the library's own `GSS_C_NT_HOSTBASED_SERVICE`, and reproduced
// with a minimal C program with no gatir or Rust code at all).
/// 1.3.6.1.5.5.2, SPNEGO (RFC 4178).
#[cfg(not(target_os = "macos"))]
const SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// 1.2.840.113554.1.2.1.4, a name like `HTTP@host` (RFC 2743, 4.1).
#[cfg(not(target_os = "macos"))]
const HOSTBASED_SERVICE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];
/// 1.2.840.113554.1.2.2.1, a name like `HTTP/host@REALM` (RFC 4121, 2.1).
#[cfg(not(target_os = "macos"))]
const KRB5_PRINCIPAL: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01];

#[cfg(not(target_os = "macos"))]
static SPNEGO_OID: Oid = Oid::of(SPNEGO);
#[cfg(not(target_os = "macos"))]
static HOSTBASED_SERVICE_OID: Oid = Oid::of(HOSTBASED_SERVICE);
#[cfg(not(target_os = "macos"))]
static KRB5_PRINCIPAL_OID: Oid = Oid::of(KRB5_PRINCIPAL);

const STATUS_CONTINUE_NEEDED: Status = 1;
/// The calling-error and routine-error fields of a major status: if either is
/// set, the call failed.
const STATUS_ERROR_MASK: Status = 0xffff_0000;
/// `GSS_C_GSS_CODE` and `GSS_C_MECH_CODE`: the two kinds of status to display.
const GSS_CODE: c_int = 1;
const MECH_CODE: c_int = 2;

type ImportName = unsafe extern "C" fn(*mut Status, *mut Buffer, *mut Oid, *mut Handle) -> Status;
type InitSecContext = unsafe extern "C" fn(
    *mut Status,   // minor status
    Handle,        // initiator credentials: none, for the default ones
    *mut Handle,   // the context
    Handle,        // the target name
    *mut Oid,      // the mechanism
    Status,        // request flags
    Status,        // time requested
    *mut c_void,   // channel bindings: none
    *mut Buffer,   // the token from the peer, none at first
    *mut *mut Oid, // the mechanism used, which is not wanted
    *mut Buffer,   // the token to send
    *mut Status,   // flags returned
    *mut Status,   // time the context is valid for
) -> Status;
type ReleaseName = unsafe extern "C" fn(*mut Status, *mut Handle) -> Status;
type ReleaseBuffer = unsafe extern "C" fn(*mut Status, *mut Buffer) -> Status;
type DeleteSecContext = unsafe extern "C" fn(*mut Status, *mut Handle, *mut Buffer) -> Status;
type DisplayStatus =
    unsafe extern "C" fn(*mut Status, Status, c_int, *mut Oid, *mut Status, *mut Buffer) -> Status;

/// The functions of the library. It is never unloaded, so they stay valid.
pub struct Gss {
    import_name: ImportName,
    init_sec_context: InitSecContext,
    release_name: ReleaseName,
    release_buffer: ReleaseBuffer,
    delete_sec_context: DeleteSecContext,
    display_status: DisplayStatus,
    /// SPNEGO, the host-based-service and the Kerberos-principal name type,
    /// as the library itself keeps them (see the comment above `Oid::of`'s
    /// callers for why: on macOS these must be the library's own, not a copy
    /// of the same bytes at a different address).
    spnego_mechanism: *const Oid,
    hostbased_service: *const Oid,
    krb5_principal_name: *const Oid,
}

// SAFETY: the three OID pointers refer either to this crate's own `'static`
// data (non-macOS) or to the loaded library's own global data (macOS, never
// unloaded, see `resolve()`); either way it is read-only and outlives every
// use of a `Gss`.
unsafe impl Send for Gss {}
unsafe impl Sync for Gss {}

impl std::fmt::Debug for Gss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gss")
    }
}

#[cfg(target_os = "macos")]
const LIBRARIES: &[&str] = &["/System/Library/Frameworks/GSS.framework/GSS"];
#[cfg(not(target_os = "macos"))]
const LIBRARIES: &[&str] = &["libgssapi_krb5.so.2", "libgssapi.so.3"];

#[cfg(target_os = "macos")]
const INSTALL: &str = "";
#[cfg(not(target_os = "macos"))]
const INSTALL: &str = ": install libgssapi-krb5-2 (Debian, Ubuntu) or krb5-libs (Fedora, RHEL)";

/// The library and its functions, loaded on the first call and kept.
pub fn load() -> Result<&'static Gss, String> {
    static GSS: OnceLock<Result<Gss, String>> = OnceLock::new();
    GSS.get_or_init(Gss::open).as_ref().map_err(String::clone)
}

impl Gss {
    fn open() -> Result<Self, String> {
        Self::open_any(LIBRARIES)
    }

    /// The first of `names` that loads, and has what is needed.
    fn open_any(names: &[&str]) -> Result<Self, String> {
        // The reason the first one failed: it is the one that is looked for first.
        let mut reason = String::new();
        for name in names {
            // SAFETY: loading a library runs its initializers, which those of
            // the system's Kerberos libraries are built for.
            match unsafe { Library::new(name) } {
                Ok(library) => return Self::resolve(library),
                Err(err) if reason.is_empty() => reason = err.to_string(),
                Err(_) => {}
            }
        }
        Err(format!(
            "none of {} could be loaded ({reason}){INSTALL}",
            names.join(", ")
        ))
    }

    fn resolve(library: Library) -> Result<Self, String> {
        macro_rules! symbol {
            ($name:literal as $type:ty) => {
                // SAFETY: the function of this name has the type that the C
                // bindings of RFC 2744 give it, which `$type` declares.
                match unsafe { library.get::<$type>(concat!($name, "\0").as_bytes()) } {
                    Ok(function) => *function,
                    Err(err) => return Err(format!("the library has no {}: {err}", $name)),
                }
            };
        }
        let import_name = symbol!("gss_import_name" as ImportName);
        let init_sec_context = symbol!("gss_init_sec_context" as InitSecContext);
        let release_name = symbol!("gss_release_name" as ReleaseName);
        let release_buffer = symbol!("gss_release_buffer" as ReleaseBuffer);
        let delete_sec_context = symbol!("gss_delete_sec_context" as DeleteSecContext);
        let display_status = symbol!("gss_display_status" as DisplayStatus);

        // On macOS these are the library's own global `gss_OID_desc` values
        // (Apple's <GSS/gssapi_oid.h> and <GSS/gssapi_spnego.h> give their
        // names), read by address the same way the functions above are, so
        // that what gatir passes is the library's own object, not a copy.
        // Elsewhere, this crate's own encoding of the same OIDs is a `static`
        // (so it too has one address for as long as the process runs), since
        // no comparable library-identity behaviour is known to matter there.
        #[cfg(target_os = "macos")]
        let (spnego_mechanism, hostbased_service, krb5_principal_name) = (
            symbol!("__gss_spnego_mechanism_oid_desc" as *const Oid),
            symbol!("__gss_c_nt_hostbased_service_oid_desc" as *const Oid),
            symbol!("__gss_krb5_nt_principal_name_oid_desc" as *const Oid),
        );
        #[cfg(not(target_os = "macos"))]
        let (spnego_mechanism, hostbased_service, krb5_principal_name): (
            *const Oid,
            *const Oid,
            *const Oid,
        ) = (&SPNEGO_OID, &HOSTBASED_SERVICE_OID, &KRB5_PRINCIPAL_OID);

        let gss = Self {
            import_name,
            init_sec_context,
            release_name,
            release_buffer,
            delete_sec_context,
            display_status,
            spnego_mechanism,
            hostbased_service,
            krb5_principal_name,
        };
        // The functions point into the library, which must stay where it is.
        std::mem::forget(library);
        Ok(gss)
    }

    /// Says what a failed call went wrong with, in the library's own words.
    fn describe(&self, major: Status, minor: Status) -> String {
        let mut parts = self.messages(major, GSS_CODE);
        if minor != 0 {
            parts.extend(self.messages(minor, MECH_CODE));
        }
        if parts.is_empty() {
            format!("GSS-API error (major status 0x{major:08x}, minor status {minor})")
        } else {
            parts.join(": ")
        }
    }

    /// The text of a status; the library may need several calls to give it all.
    fn messages(&self, status: Status, kind: c_int) -> Vec<String> {
        let mut found = Vec::new();
        let mut more: Status = 0;
        // What the library keeps in `more` says where to go on; a bound keeps a
        // library that never says it is done from looping.
        for _ in 0..8 {
            let mut minor = 0;
            let mut text = Buffer::EMPTY;
            // SAFETY: the pointers are to places on the stack, valid for the
            // call; a null mechanism asks for the default one.
            let major = unsafe {
                (self.display_status)(&mut minor, status, kind, null_mut(), &mut more, &mut text)
            };
            if major & STATUS_ERROR_MASK != 0 {
                break;
            }
            let line = self.take(&mut text);
            if let Some(line) = line.map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
                && !line.is_empty()
            {
                found.push(line);
            }
            if more == 0 {
                break;
            }
        }
        found
    }

    /// The bytes of a buffer that the library filled, which are given back.
    fn take(&self, buffer: &mut Buffer) -> Option<Vec<u8>> {
        if buffer.value.is_null() {
            return None;
        }
        // SAFETY: the library says the buffer holds `length` bytes, and it stays
        // valid until it is released, right after.
        let bytes = unsafe { std::slice::from_raw_parts(buffer.value.cast::<u8>(), buffer.length) }
            .to_vec();
        let mut minor = 0;
        // SAFETY: the buffer was allocated by the library, and is not used again.
        unsafe { (self.release_buffer)(&mut minor, buffer) };
        Some(bytes)
    }
}

/// The name of a service, as the library keeps it.
pub struct Name {
    gss: &'static Gss,
    handle: Handle,
}

// SAFETY: a name is not shared: it is used from one thread at a time, and the
// library does not tie it to the thread that made it.
unsafe impl Send for Name {}

impl Name {
    /// Imports `service`: `HTTP@host`, or a Kerberos principal if `principal`.
    pub fn import(gss: &'static Gss, service: &str, principal: bool) -> Result<Self, String> {
        let mut input = Buffer::over(service.as_bytes());
        let kind = if principal {
            gss.krb5_principal_name
        } else {
            gss.hostbased_service
        };
        let mut handle = null_mut();
        let mut minor = 0;
        // SAFETY: `input` describes bytes that live through the call, and the
        // library copies what it keeps; `kind` is the library's own OID, read
        // only; `handle` and `minor` are places for the results.
        let major =
            unsafe { (gss.import_name)(&mut minor, &mut input, kind.cast_mut(), &mut handle) };
        if major & STATUS_ERROR_MASK != 0 {
            return Err(gss.describe(major, minor));
        }
        Ok(Self { gss, handle })
    }
}

impl Drop for Name {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: the name was made by the library and is not used again; it
        // may be null if the call that made it did not set it, which the
        // library accepts.
        unsafe { (self.gss.release_name)(&mut minor, &mut self.handle) };
    }
}

/// A security context with one service: what the rounds of the exchange share.
pub struct Context {
    gss: &'static Gss,
    handle: Handle,
    /// Released after the context, which refers to it: fields drop in order.
    name: Name,
    complete: bool,
}

// SAFETY: as for `Name`. A context is used by one round at a time, and the
// exchange of a connection moves it from thread to thread between rounds.
unsafe impl Send for Context {}

impl Context {
    pub fn new(name: Name) -> Self {
        Self {
            gss: name.gss,
            handle: null_mut(),
            name,
            complete: false,
        }
    }

    /// Whether the context is established: nothing more is expected from the peer.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// The next round, with SPNEGO and the default credentials, which are the
    /// ticket cache of the logged-in user: `from_parent` is the token the peer
    /// sent, or `None` for the first. The token to send, if there is one.
    pub fn step(&mut self, from_parent: Option<&[u8]>) -> Result<Option<Vec<u8>>, String> {
        let mut minor = 0;
        let mechanism = self.gss.spnego_mechanism;
        let mut input = from_parent.map(Buffer::over);
        let mut output = Buffer::EMPTY;
        let (mut flags, mut valid_for) = (0, 0);
        // SAFETY: `handle` is null at the first round, which makes a context,
        // and a context of this one after; `name` lives as long as it does;
        // the mechanism and the input describe bytes that live through the
        // call; a null input means there is no token from the peer, null
        // credentials the default ones, and null channel bindings none; the
        // library fills `output`, `flags` and `valid_for`.
        let major = unsafe {
            (self.gss.init_sec_context)(
                &mut minor,
                null_mut(),
                &mut self.handle,
                self.name.handle,
                mechanism.cast_mut(),
                0,
                0,
                null_mut(),
                input.as_mut().map_or(null_mut(), std::ptr::from_mut),
                null_mut(),
                &mut output,
                &mut flags,
                &mut valid_for,
            )
        };
        // What the library allocated is copied out and given back, whether or
        // not the call went well.
        let token = self.gss.take(&mut output).filter(|bytes| !bytes.is_empty());
        if major & STATUS_ERROR_MASK != 0 {
            return Err(self.gss.describe(major, minor));
        }
        self.complete = major & STATUS_CONTINUE_NEEDED == 0;
        Ok(token)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }
        let mut minor = 0;
        // SAFETY: the context was made by the library and is not used again; a
        // null output token says that none is wanted.
        unsafe { (self.gss.delete_sec_context)(&mut minor, &mut self.handle, null_mut()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A library that every process has, and that is not a GSS-API.
    #[cfg(target_os = "macos")]
    const NOT_GSS: &str = "/usr/lib/libSystem.B.dylib";
    #[cfg(not(target_os = "macos"))]
    const NOT_GSS: &str = "libc.so.6";

    #[test]
    fn the_library_of_the_system_loads() {
        assert!(load().is_ok(), "{:?}", load().err());
    }

    #[test]
    fn a_missing_library_is_told_by_its_name() {
        let err = Gss::open_any(&["libno-such-gssapi.so.99", "libnor-this.so.99"])
            .expect_err("no such library");
        assert!(
            err.contains("libno-such-gssapi.so.99, libnor-this.so.99 could be loaded"),
            "{err}"
        );
    }

    #[test]
    fn a_library_without_the_functions_is_told_by_the_first_one_missing() {
        let err = Gss::open_any(&[NOT_GSS]).expect_err("not a GSS-API");
        assert!(err.contains("has no gss_import_name"), "{err}");
    }

    #[test]
    fn the_library_says_what_went_wrong_in_words() {
        let gss = load().unwrap();
        // GSS_S_BAD_MECH, in the routine-error field of a major status.
        let text = gss.describe(1 << 16, 0);
        assert!(
            !text.is_empty() && !text.starts_with("GSS-API error"),
            "{text}"
        );
    }

    #[test]
    fn a_status_the_library_cannot_explain_is_still_reported() {
        let gss = load().unwrap();
        // No routine error of this number exists, and no minor status either
        // that a library knows: what comes back names the numbers, or the
        // library's own "unknown" text. Either way there is something to read.
        assert!(!gss.describe(0x00f0_0000, 0xfff0_0000).is_empty());
    }

    #[test]
    fn both_kinds_of_service_name_are_imported() {
        let gss = load().unwrap();
        for (service, principal) in [
            ("HTTP@proxy.example.com", false),
            ("HTTP/proxy.example.com@EXAMPLE.COM", true),
        ] {
            assert!(Name::import(gss, service, principal).is_ok(), "{service}");
        }
    }
}
