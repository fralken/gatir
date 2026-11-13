# Making a release

A release is a tag. Pushing a tag that starts with `v` runs the workflow in
`.github/workflows/release.yml`, which builds gatir on every target, tests it,
packs it, and publishes the archives and a file of their checksums as a GitHub
release.

## Steps

1. Set the new version in `Cargo.toml` (`[workspace.package]`), run `cargo build`
   so that `Cargo.lock` follows, and commit both.
2. Tag that commit, with the version prefixed by `v`, and push the tag:

   ```sh
   git tag -a v0.1.0 -m "gatir 0.1.0"
   git push origin v0.1.0
   ```

   The first job of the workflow stops the release if the tag and the version in
   `Cargo.toml` differ.
3. When the jobs are done, the release is on the page of the repository, with the
   notes made from the commits since the previous tag.

To see what a release would hold without making one, run the workflow by hand from
the Actions tab. It builds and packs everything and keeps the archives as artifacts
of that run; nothing is published.

## What is in a release

| File | For |
|---|---|
| `gatir-<version>-x86_64-unknown-linux-gnu.tar.gz` | Linux, x86-64 |
| `gatir-<version>-aarch64-unknown-linux-gnu.tar.gz` | Linux, ARM64 |
| `gatir-<version>-aarch64-apple-darwin.tar.gz` | macOS, Apple silicon |
| `gatir-<version>-x86_64-apple-darwin.tar.gz` | macOS, Intel |
| `gatir-<version>-x86_64-pc-windows-msvc.zip` | Windows, x86-64 |
| `gatir_<version>-1_amd64.deb`, `gatir_<version>-1_arm64.deb` | Debian and Ubuntu |
| `gatir-<version>-1.x86_64.rpm`, `gatir-<version>-1.aarch64.rpm` | Fedora and other RPM systems |
| `gatir-<version>-x64.msi` | Windows, x86-64, as an installer |
| `gatir.rb` | the Homebrew formula of the release |
| `SHA256SUMS` | the checksum of each of the files above but the formula |

An archive holds one directory with the program, the two licenses, the README,
`gatir.example.toml`, the documentation and, except on Windows, the manual pages
(`man/man1`, written by `crates/mangen` from the command-line definition). The
packages hold the same files where their systems keep them (`/usr/bin/gatir`,
`/usr/share/doc/gatir`), and nothing else: no service, no file in `/etc`.

### What the Linux builds need

The Linux builds are made on Ubuntu 22.04, so they need:

- its C library or newer: glibc 2.35, that is Debian 12, Ubuntu 22.04, Fedora 36
  and later. Not RHEL 9 or its rebuilds, whose glibc is older.
- OpenSSL 3 (`libssl3`).

Both are linked when the program starts.

Kerberos goes through the system's library, `libgssapi_krb5` (package
`libgssapi-krb5-2`), which gatir does not link. It opens the library only when
Negotiate is configured, so a computer without it can still run gatir with NTLM,
and Negotiate says which library is missing. This was checked in a container
with the library removed.

The packages declare these needs, and their tools install what is missing:
`sudo apt install ./gatir_<version>-1_<arch>.deb` fetches `libssl3`, and the
Kerberos library too unless recommended packages are turned off; `dnf install`
does the same for the `.rpm`. `dpkg-shlibdeps` and `rpmbuild` work out what each
package requires from the program itself, so nothing is written by hand. With
an archive, the user installs them.

The packages name `Francesco MDE <6103677+fralken@users.noreply.github.com>` as
their maintainer, unless `GATIR_MAINTAINER` gives another, in the form
`Name <address>`. That address is a GitHub privacy relay that receives no mail:
open an issue on the repository instead. The packages are not signed: check them
with `SHA256SUMS`.

### Homebrew

`gatir.rb` installs the macOS archive of its release. Homebrew reads formulae from
a tap: a repository named `homebrew-<name>` with the formula in its `Formula`
directory. gatir's tap is `fralken/homebrew-tap`. To publish a release there,
copy `gatir.rb` to its `Formula` directory and push. Users then install it with:

```sh
brew install fralken/tap/gatir
```

`scripts/homebrew-formula.sh REPOSITORY TAG SHA256SUMS` writes the formula for
any release. The formula is for macOS only: on Linux, use the package or the
archive.

### The Windows installer

`gatir-<version>-x64.msi` installs `gatir.exe` under Program Files and adds that
folder to the `PATH`, so a new terminal can run `gatir` without its path.
Uninstalling undoes both. Installing a newer version removes the older one first
(a major upgrade, done by Windows Installer itself). There is no setup wizard:
double-clicking the file shows the usual Windows Installer progress dialog, and

```powershell
msiexec /i gatir-<version>-x64.msi /quiet
```

installs it without asking anything, which is also how to roll it out to many
computers. The installer is built for x86-64; on Arm64 Windows it runs under
emulation, as `gatir.exe` itself does.

Installing needs an administrator, since it writes to Program Files and to every
user's `PATH`. Without one, use the `.zip`, which needs no privilege: extract it
anywhere in your own folders, and add it to your own `PATH`:

```powershell
setx PATH "%PATH%;C:\path\to\the\extracted\folder"
```

Then open a new terminal, as with the installer. With only the `.msi`,
`msiexec /a gatir-<version>-x64.msi /qn TARGETDIR=C:\path\to\extract\to` copies
out its files without installing anything.

## Checking a download

Put the archive and `SHA256SUMS` in one directory, and check the archive that was
downloaded:

```sh
sha256sum --check --ignore-missing SHA256SUMS      # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS  # macOS
```

## Packing by hand

The workflow calls these scripts, so what you build by hand is what is released:

- `scripts/package.sh [TARGET]` builds one target in release mode, and writes the
  archive and its `.sha256` file to `dist/`.
- `scripts/package-linux.sh [TARGET]` makes the `.deb` and the `.rpm` from a Linux
  archive. It needs `dpkg-dev` and `rpm`.
- `scripts/package-windows.sh [TARGET]` makes the `.msi` from a Windows archive.
  It needs `wixl` (`brew install msitools` on macOS).

None of them needs Windows or WiX, so the `.msi` can be made and inspected
(`msiinfo tables`, `msiextract`, from the same `msitools`) on any computer that
builds gatir.

One exception: the `wixl` that Debian and Ubuntu ship (0.103 at the time of
writing) is too old for the `<Environment>` element, which puts gatir on the
`PATH`. Build the `.msi` on macOS until a newer `wixl` reaches their
repositories. This is also why the workflow's `.msi` job runs on macOS, while
the others run on Linux.

The workflow runs only on GitHub. If a release fails, look first at what it
depends on there: the names of the runners, and the actions it uses.
