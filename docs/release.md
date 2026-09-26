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
| `gatir.rb` | the Homebrew formula of the release |
| `SHA256SUMS` | the checksum of each of the files above but the formula |

An archive holds one directory with the program, the two licenses, the README,
`gatir.example.toml`, the documentation and, except for Windows, the manual pages
(`man/man1`, written by `crates/mangen` from the command-line definition). The packages hold the same, in the places
their systems keep them (`/usr/bin/gatir`, `/usr/share/doc/gatir`), and nothing else:
no service, no file in `/etc`.

### What the Linux builds need

The Linux builds are made on Ubuntu 22.04, so they need a system with at least its
C library (glibc 2.35: Debian 12, Ubuntu 22.04, Fedora 36 and their successors; not
RHEL and its rebuilds 9, whose glibc is older), OpenSSL 3 (`libssl3`) and, since
Kerberos goes through the system's library, `libgssapi_krb5` (`libgssapi-krb5-2`). Both
libraries are linked when the program starts: without them it does not start at all,
even to use NTLM only (tried on a clean Debian 12).

The packages say so, and their tools install what is missing: `sudo apt install
./gatir_<version>-1_<arch>.deb` fetches `libssl3` and the Kerberos libraries, and `dnf
install` does the same for the .rpm. What each package requires is worked out from the
program itself, by `dpkg-shlibdeps` and by `rpmbuild`, not written by hand. For the
archives it is for the user to install them.

The maintainer written in the packages is `The gatir contributors
<gatir@example.invalid>` until `GATIR_MAINTAINER` says otherwise, in the form `Name
<address>`. The packages are not signed: check them with `SHA256SUMS`.

### Homebrew

`gatir.rb` installs the macOS archive of its release. Homebrew reads formulae from a
tap, which is a repository named `homebrew-<something>` with the formula in its
`Formula` directory. Copy `gatir.rb` there, and

```sh
brew tap <owner>/<something>
brew install gatir
```

`scripts/homebrew-formula.sh REPOSITORY TAG SHA256SUMS` writes the formula for any
release. It is for macOS only: on Linux, use the package or the archive.

## Checking a download

Put the archive and `SHA256SUMS` in one directory, and check the archive that was
downloaded:

```sh
sha256sum --check --ignore-missing SHA256SUMS      # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS  # macOS
```

## Packing by hand

`scripts/package.sh [TARGET]` does what the workflow does for one target: it builds
in release mode, then writes the archive and its `.sha256` file to `dist/`.
`scripts/package-linux.sh [TARGET]` then makes the `.deb` and the `.rpm` from it (it needs
`dpkg-dev` and `rpm`). The workflow calls both, so that what is tried here is what is released.

The workflow is not run anywhere but on GitHub. What it depends on there (the
names of the runners, the actions it uses) is the part to look at first if a release
fails.
