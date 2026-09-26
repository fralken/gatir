# gatir

gatir is a local proxy that logs in to your company's proxy for you. Programs
that cannot do NTLM or Kerberos themselves (a browser, `curl`, `git`, `pip`, a
build tool) talk to gatir on your own machine, and gatir authenticates to the
corporate proxy on their behalf, so nobody has to type a password. It is
inspired by CNTLM, and is written in Rust.

- **HTTP proxy** for plain requests and `CONNECT` tunnels, with connections to the
  parent kept and reused.
- **Authentication to the parent**: NTLM (v2, and the older forms), and Kerberos
  (Negotiate) with the ticket of the logged-in user. A password can be replaced by
  its hash, so that it is not kept in a file.
- **Proxy auto-configuration**: a PAC script from a file or an `http(s)` address,
  kept up to date, chooses the parent for each request, with `no_proxy` on top.
- **SOCKS5** server, and **local port forwarding** (`-L`), for programs that do
  not use HTTP proxies.
- **Reload**: `kill -HUP` makes a running gatir read its configuration again.
- Care with accounts: gatir does not hammer a parent with wrong credentials, since
  each failed attempt is a failed logon that can lock the account.

## Quick start

```sh
gatir hash                                   # an nt_hash line, to put in place of a password
mkdir -p ~/.config/gatir
cp gatir.example.toml ~/.config/gatir/gatir.toml
chmod 600 ~/.config/gatir/gatir.toml         # then edit it
gatir config check                           # says what it understood, without secrets
gatir run
```

Then point a program at `http://127.0.0.1:3128`, for instance
`curl -x http://127.0.0.1:3128 https://example.com/`.

`gatir --help` lists the options. A command-line option takes the place of the same
setting in the file.

## Where it runs

| System | Status |
|---|---|
| Linux | Supported. Needs OpenSSL 3 (`libssl3`) and the Kerberos library (`libgssapi-krb5-2`) installed: without them gatir does not start, even if you use NTLM only. |
| macOS | Supported, on Apple silicon and Intel. Kerberos uses the system's. |
| Windows | Builds, but has not been tried yet. Negotiate through SSPI is not written: use NTLM. |

## Documentation

- [Configuration](docs/configuration.md): where the file is, who may read it, reloading.
- [PAC scripts](docs/pac.md), [ports forwarded through the proxy](docs/tunnels.md),
  [the SOCKS5 server](docs/socks5.md).
- [Making a release](docs/release.md), and [the specifications gatir follows](docs/references.md).
- [Notes for contributors](AGENTS.md).

## License

Licensed under either of the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.
