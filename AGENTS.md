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
  `auth` modules, held in `secrecy`/`zeroize` types, and never logged.
- Never commit real credentials, hashes, internal hostnames or PAC files.
  `*.conf` and `*.pac` are git-ignored; examples use the `.example.toml`
  suffix and synthetic values. Tests use synthetic credentials only.

## Layout

- `crates/gatir`: library + `gatir` binary.
- `crates/testkit`: dev-only test support (mock origin/parent proxies,
  injectable clock and nonce). Never a dependency of the shipped binary.

## Commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Kerberos (Negotiate) goes through the system GSS-API on Unix, so building
there needs libclang (bindgen), which the macOS command line tools include, and
on Linux also `libkrb5-dev`. At run time Linux needs the system Kerberos
library (`libgssapi_krb5`). Windows is not supported for Negotiate yet.

`rust-toolchain.toml` selects the `stable` channel and `rust-version` in the
workspace `Cargo.toml` is the minimum supported Rust version. CI runs the same
checks on Linux, macOS and Windows, plus `cargo deny`.

## Workflow

Development proceeds in small steps. Each step must be runnable and verified
(automated tests, plus manual checks where a real proxy or domain is needed)
before the next one starts.
