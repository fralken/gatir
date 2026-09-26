#!/usr/bin/env bash
# Builds gatir in release mode and packs it, with its licenses, README, example
# configuration and documentation, into dist/gatir-<version>-<target>.tar.gz (a
# .zip for Windows) next to a .sha256 file that `sha256sum -c` or
# `shasum -a 256 -c` checks. The release workflow runs this on every target;
# it can be run by hand to see what a release holds.
#
#   scripts/package.sh [TARGET]    TARGET is a Rust target triple; the default is this machine's.
set -euo pipefail

cd "$(dirname "$0")/.."

target="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
[ -n "$version" ] || { echo "cannot read the version from Cargo.toml" >&2; exit 1; }

case "$target" in
  *windows*) exe="gatir.exe"; ext="zip" ;;
  *)         exe="gatir";     ext="tar.gz" ;;
esac

cargo build --release --locked -p gatir --target "$target"

name="gatir-${version}-${target}"
stage="dist/stage/${name}"
rm -rf "dist/stage/${name}" "dist/${name}.${ext}" "dist/${name}.${ext}.sha256"
mkdir -p "$stage"

cp "target/${target}/release/${exe}" "$stage/"
cp README.md LICENSE-MIT LICENSE-APACHE gatir.example.toml "$stage/"
cp -R docs "$stage/docs"

archive="dist/${name}.${ext}"
if [ "$ext" = "zip" ]; then
  if command -v 7z >/dev/null 2>&1; then
    (cd dist/stage && 7z a -tzip -bso0 "../${name}.zip" "${name}")
  else
    (cd dist/stage && powershell.exe -NoProfile -Command \
      "Compress-Archive -Path '${name}' -DestinationPath '../${name}.zip'")
  fi
else
  tar -czf "$archive" -C dist/stage "${name}"
fi

# The checksum file names the archive without its directory, so that it is checked
# from the directory the archive was downloaded to.
if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum "${name}.${ext}" > "${name}.${ext}.sha256")
else
  (cd dist && shasum -a 256 "${name}.${ext}" > "${name}.${ext}.sha256")
fi

echo "$archive"
cat "${archive}.sha256"
