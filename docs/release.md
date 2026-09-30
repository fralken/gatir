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
`gatir.example.toml`, the documentation and, except for Windows, the manual pages
(`man/man1`, written by `crates/mangen` from the command-line definition). The packages hold the same, in the places
their systems keep them (`/usr/bin/gatir`, `/usr/share/doc/gatir`), and nothing else:
no service, no file in `/etc`.

### What the Linux builds need

The Linux builds are made on Ubuntu 22.04, so they need a system with at least its
C library (glibc 2.35: Debian 12, Ubuntu 22.04, Fedora 36 and their successors; not
RHEL and its rebuilds 9, whose glibc is older) and OpenSSL 3 (`libssl3`), which are
linked when the program starts.

Kerberos goes through the system's library, `libgssapi_krb5` (`libgssapi-krb5-2`), which
gatir does not link: it opens the library when Negotiate is configured, so a computer
without it can run gatir with NTLM, and Negotiate says which library is missing (checked
in a container with the library removed). The packages recommend it.

The packages say so, and their tools install what is missing: `sudo apt install
./gatir_<version>-1_<arch>.deb` fetches `libssl3`, and the Kerberos library as well
unless recommended packages are turned off; `dnf install` does the same for the .rpm.
What each package requires is worked out from the program itself, by `dpkg-shlibdeps`
and by `rpmbuild`, not written by hand. For the archives it is for the user to install
them.

The maintainer written in the packages is `Francesco MDE
<6103677+fralken@users.noreply.github.com>` unless `GATIR_MAINTAINER` says otherwise, in
the form `Name <address>`. That address is a GitHub-privacy relay: it does not receive
mail, so open an issue on the repository instead of writing to it. The packages are not
signed: check them with `SHA256SUMS`.

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

### The Windows installer

`gatir-<version>-x64.msi` installs `gatir.exe` under Program Files and adds that
folder to the `PATH`, so that `gatir` can be run from a new terminal without naming
its path; both are undone when it is uninstalled. Installing a newer version removes
the older one first (a major upgrade, by the Windows Installer itself). There is no
setup wizard: double-clicking the file shows the ordinary Windows Installer progress
dialog, and

```powershell
msiexec /i gatir-<version>-x64.msi /quiet
```

installs it without asking anything, which is also how it would be rolled out to
several computers. The installer needs Windows to be x86-64: on Arm64 Windows it runs
under emulation, as `gatir.exe` itself does.

Installing it needs an administrator, since it writes to Program Files and to the
`PATH` of every user. Without one, the `.zip` works with no privilege at all: extract
it anywhere in your own folders, and put it on your own `PATH` instead of the
computer's:

```powershell
setx PATH "%PATH%;C:\path\to\the\extracted\folder"
```

(open a new terminal afterwards, as with the installer). With only the `.msi` in
hand, `msiexec /a gatir-<version>-x64.msi /qn TARGETDIR=C:\path\to\extract\to` copies
out its files the same way, without installing anything.

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
`dpkg-dev` and `rpm`), and `scripts/package-windows.sh [TARGET]` makes the `.msi` from a
Windows one (it needs `wixl`, `brew install msitools` on macOS). None of the three needs
Windows or a copy of WiX itself, so the `.msi` can be made, and tried (`msiinfo tables`,
`msiextract`, from the same formula) on any machine that builds gatir — except that
Debian and Ubuntu's own `wixl` package (0.103 as of this writing) is too old for the
`<Environment>` element the `.wxs` uses to put gatir on the `PATH`; use macOS for this
one until a newer `wixl` reaches their repositories (this is also why the workflow's own
`.msi` job runs on macOS, not Linux like the rest). The workflow calls all of these
tools, so that what is tried here is what is released.

The workflow is not run anywhere but on GitHub. What it depends on there (the
names of the runners, the actions it uses) is the part to look at first if a release
fails.
