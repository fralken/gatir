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

| File | Target |
|---|---|
| `gatir-<version>-x86_64-unknown-linux-gnu.tar.gz` | Linux, x86-64 |
| `gatir-<version>-aarch64-unknown-linux-gnu.tar.gz` | Linux, ARM64 |
| `gatir-<version>-aarch64-apple-darwin.tar.gz` | macOS, Apple silicon |
| `gatir-<version>-x86_64-apple-darwin.tar.gz` | macOS, Intel |
| `gatir-<version>-x86_64-pc-windows-msvc.zip` | Windows, x86-64 |
| `SHA256SUMS` | the checksum of each archive |

An archive holds one directory with the program, the two licenses, the README,
`gatir.example.toml` and the documentation. The Linux archives are built on Ubuntu
22.04, so they need a system at least as recent, with OpenSSL 3 (`libssl3`) and, since
Kerberos goes through the system's library, `libgssapi_krb5` (`libgssapi-krb5-2`)
installed. Both are linked when the program starts: on a system without them it does
not start at all, even to use NTLM only (tried on a clean Debian 12). A package for a
distribution can declare them as dependencies; for the archives, it is for the user to
install them.

## Checking a download

Put the archive and `SHA256SUMS` in one directory, and check the archive that was
downloaded:

```sh
sha256sum --check --ignore-missing SHA256SUMS      # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS  # macOS
```

## Packing by hand

`scripts/package.sh [TARGET]` does what the workflow does for one target: it builds
in release mode, then writes the archive and its `.sha256` file to `dist/`. The
workflow calls it, so that what is tried here is what is released.

The workflow is not run anywhere but on GitHub. What it depends on there (the
names of the runners, the actions it uses) is the part to look at first if a release
fails.
