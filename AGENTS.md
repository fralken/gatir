# gatir

gatir is a local HTTP proxy that authenticates to a corporate parent proxy
(NTLM/NTLMv2, Kerberos, Windows SSPI) so the user never has to type
credentials. It targets macOS, Linux and Windows from day one. Inspired by
CNTLM.

## Conventions

- **Everything is in English**: code, comments, log/CLI/error messages,
  documentation (README, man pages, rustdoc), commit messages, PR titles and
  descriptions.
- Comments only where the *why* is non-obvious. No comments that restate code.
- Prefer well-known, audited crates over hand-written protocol or crypto code.
  New dependencies must pass `cargo deny`.
- `unsafe` is denied workspace-wide. If a platform binding (SSPI, GSSAPI)
  needs it, allow it in that single module with a comment explaining why.
- gatir is an original work. Implement from public specifications (RFCs,
  MS-NLMP, the PAC documentation) and black-box behavior. Do not copy or
  translate code, comments, tests, help text or documentation from other
  projects. Documentation mentions CNTLM only to say that gatir is inspired
  by it.
- The specifications the code follows are listed in `docs/references.md`, with
  the revision used. Add a new one there when code starts to depend on it.

## Security rules

- Passwords, NT/NTLMv2 hashes and tokens are handled only in the `config` and
  `auth` modules, held in `secrecy`/`zeroize` types, and never logged. The one
  exception is the password a SOCKS5 client offers: `proxy::socks5` reads it
  into a `Zeroizing` buffer, hands it to `config` to compare, and drops it.
- Never commit real credentials, hashes, internal hostnames or PAC files.
  `*.conf` and `*.pac` are git-ignored; examples use the `.example.toml`
  suffix and synthetic values. Tests use synthetic credentials only.

## Layout

- `crates/gatir`: library + `gatir` binary.
- `crates/testkit`: dev-only test support (mock origin/parent proxies,
  injectable clock and nonce). Never a dependency of the shipped binary.

## Commands

A fresh checkout needs the Rust toolchain (`rustup`; `rust-toolchain.toml` then
picks the version) and, before `cargo build` works:

- **macOS**: the Xcode Command Line Tools (`xcode-select --install`).
- **Linux**: a C compiler (`build-essential` on Debian and Ubuntu), `libssl-dev`
  and `pkg-config`. Running the tests also needs the Kerberos library at run
  time: `libgssapi-krb5-2` (Debian, Ubuntu) or `krb5-libs` (Fedora, RHEL).
- **Windows**: the MSVC Build Tools (Visual Studio Installer, "Desktop
  development with C++").

Why each of these is needed is explained further down, where it is relevant.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The parsers that read what others send (the NTLM challenge, SOCKS5, the PAC
script and its result, the configuration, addresses, `Proxy-Authenticate`) have
`fuzz_` tests: they start from valid inputs and change them in thousands of
ways (`gatir_testkit::fuzz`), and ask that nothing panics or takes for ever and
that what is accepted is safe to use. The inputs are the same on every run, so a
failure can be repeated, and it names the input in hex. For a longer search:

```sh
GATIR_FUZZ_SCALE=100 cargo test fuzz_
```

A new parser gets a `fuzz_` test of its own, and a defect it finds becomes an
ordinary test before it is fixed.

Kerberos (Negotiate) goes through the system GSS-API on Unix, which gatir loads
at run time (`libloading`, in `auth/negotiate/gss/api.rs`) instead of linking it:
nothing about it is needed to build, and a computer without the library
(`libgssapi_krb5` on Linux) can still run gatir with NTLM. The tests do load it, so
Linux needs `libgssapi-krb5-2` to run them. On Windows, Negotiate goes through SSPI
(`windows-sys`), in `auth/negotiate/sspi/api.rs`. Those two files are the places
where `unsafe` is allowed.

TLS (a PAC script fetched over https) goes through the operating system, with
the `native-tls` crate: Security.framework on macOS, Schannel on Windows and
OpenSSL on Linux, so building on Linux needs `libssl-dev` and `pkg-config`, and
running needs `libssl`. The authorities trusted are the system's. gatir ships no
TLS implementation of its own. The test server (`crates/testkit`, `tls.rs`) is
rustls with `ring` and makes its certificates with `rcgen`: dev-dependencies
only, and a different implementation from the code under test on purpose.

The PAC engine is QuickJS, through the `rquickjs` crate: C code compiled at
build time, so a C compiler is needed (the macOS command line tools, gcc or
clang on Linux, MSVC on Windows). It is the one place where C is accepted, for
want of an embeddable Rust engine with time and memory limits, and it stays
behind `pac::engine`: nothing else in the project calls into it.

`rust-toolchain.toml` selects the `stable` channel and `rust-version` in the
workspace `Cargo.toml` is the minimum supported Rust version. CI runs the same
checks on Linux, macOS and Windows, plus `cargo deny`.

## Workflow

Development proceeds in small steps. Each step must be runnable and verified
(automated tests, plus manual checks where a real proxy or domain is needed)
before the next one starts.
