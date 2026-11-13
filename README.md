# gatir

gatir is a local proxy that logs in to your company's proxy for you. Programs
that cannot do NTLM or Kerberos themselves (a browser, `curl`, `git`, `pip`, a
build tool) talk to gatir on your own computer, and gatir passes their requests
on to the corporate proxy, which these documents call the *parent*,
authenticating as you. Nobody has to type a password. gatir is inspired by
CNTLM, and is written in Rust.

- **HTTP proxy** for plain requests and `CONNECT` tunnels. Connections to the
  parent are kept and reused.
- **Authentication to the parent**: NTLM (v2, and the older forms), and Kerberos
  (Negotiate) with the ticket of the logged-in user. Instead of the password,
  the configuration can hold a hash of it.
- **Proxy auto-configuration**: a PAC script chooses the parent for each
  request. It can come from a file, an `http(s)` address, or (on macOS and
  Windows) your system's proxy settings, and is checked for changes.
  `no_proxy` applies first, and a few hosts can be sent to other proxies than
  the script says.
- **SOCKS5** server, and **local port forwarding** (`-L`), for programs that do
  not use HTTP proxies.
- **Reload**: `kill -HUP` makes a running gatir read its configuration again.
- **Care with accounts**: every failed login counts toward locking the account,
  so gatir never retries wrong credentials in a loop.

## Install

Download the file for your system from the releases page, and check it against
`SHA256SUMS`:

- **Debian, Ubuntu**: `sudo apt install ./gatir_<version>-1_<arch>.deb`
- **Fedora**: `sudo dnf install ./gatir-<version>-1.<arch>.rpm`
- **macOS**: `brew install fralken/tap/gatir`, or the archive
- **Windows**: the `.msi`, which puts `gatir.exe` on your `PATH`
- **Any system**: the archive; put the `gatir` program on your `PATH`

## Quick start

1. Copy the example configuration to `~/.config/gatir/gatir.toml`:

   ```sh
   mkdir -p ~/.config/gatir
   cp /usr/share/doc/gatir/examples/gatir.example.toml ~/.config/gatir/gatir.toml
   chmod 600 ~/.config/gatir/gatir.toml
   ```

   The example is in `/usr/share/doc/gatir/examples/` with the Debian and
   Fedora packages, in `$(brew --prefix)/share/doc/gatir/` with Homebrew, next
   to `gatir.exe` on Windows (use `%APPDATA%\gatir\gatir.toml` there), and at
   the top of the archive.

2. Edit it: set `parents` to your corporate proxy, and `username`, `domain`
   and `password` under `[credentials]`. To keep the password out of the file,
   run `gatir hash` and put the `nt_hash` line it prints in its place. If your
   computer is in a Windows domain or has a Kerberos ticket, try
   `method = "negotiate"` instead, which needs no password.

3. Check what gatir understood (secrets are never printed):

   ```sh
   gatir config check
   ```

4. If you are not sure which method the proxy accepts, ask it. Each attempt is
   a real login, so check the password first:

   ```sh
   gatir detect --url http://example.com/
   ```

5. Start gatir:

   ```sh
   gatir run
   ```

6. Point your programs at it. Most command-line tools read these variables:

   ```sh
   export http_proxy=http://127.0.0.1:3128
   export https_proxy=http://127.0.0.1:3128
   curl https://example.com/
   ```

   Browsers and other programs have their own proxy settings: set them to
   `127.0.0.1`, port `3128`.

[Settings](docs/settings.md) lists everything the file can say. `gatir --help`
lists the commands, and `man gatir` (with `man gatir-run` and the other commands)
describes the files, the environment and the signals. An option on the command
line replaces the same setting from the file.

## Where it runs

| System | Status |
|---|---|
| Linux | Supported on glibc 2.35 or later (Debian 12, Ubuntu 22.04, Fedora 36). Needs OpenSSL 3 (`libssl3`): the packages install it; with the archive, install it yourself. Kerberos uses the system's library (`libgssapi-krb5-2`), loaded only when Negotiate is configured: the packages recommend it, and without it NTLM still works. |
| macOS | Supported, on Apple silicon and Intel. Kerberos uses the system's library. |
| Windows | Supported. NTLM with a password or a hash works as elsewhere. Negotiate uses SSPI, with the identity of the logged-on user, and has been tried against a real corporate proxy; see [Authentication](docs/authentication.md). |

## Documentation

- [Settings](docs/settings.md): every setting of the configuration file, with its default.
- [Configuration](docs/configuration.md): where the file is, who may read it, reloading.
- [Authentication](docs/authentication.md): NTLM, Negotiate (Kerberos, and SSPI on Windows), and how to find out why one fails.
- [A parent that does not work](docs/failover.md): when gatir moves on to the next one, and what it remembers.
- [PAC scripts](docs/pac.md) ([why its engine is QuickJS-ng](docs/pac-engine.md)),
  [ports forwarded through the proxy](docs/tunnels.md), [the SOCKS5 server](docs/socks5.md).
- [Making a release](docs/release.md), [load-testing gatir](docs/load-testing.md), and [the specifications gatir follows](docs/references.md).
- [Notes for contributors](AGENTS.md).

## License

Licensed under either of the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.
