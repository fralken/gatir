#!/usr/bin/env bash
# Makes a .deb and an .rpm of a Linux build that scripts/package.sh has already
# packed, into dist/, each next to a .sha256 file. What the package needs from the
# system (OpenSSL 3, the C library) is worked out from the program by the tools of
# each format, not written here: `dpkg-shlibdeps` for the .deb and `rpmbuild` for
# the .rpm. The Kerberos library is not among it: gatir loads it when Negotiate is
# used, so the packages recommend it and do not require it.
#
#   scripts/package-linux.sh [TARGET]    TARGET is x86_64-unknown-linux-gnu or aarch64-unknown-linux-gnu;
#                                        the default is this machine's.
#
# It needs dpkg-dev and rpm. GATIR_MAINTAINER sets the maintainer of the packages,
# as "Name <address>".
set -euo pipefail

cd "$(dirname "$0")/.."

target="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
case "$target" in
  x86_64-unknown-linux-gnu)  deb_arch=amd64; rpm_arch=x86_64 ;;
  aarch64-unknown-linux-gnu) deb_arch=arm64; rpm_arch=aarch64 ;;
  *) echo "packages are made for Linux targets only, not ${target}" >&2; exit 1 ;;
esac
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
maintainer="${GATIR_MAINTAINER:-Francesco MDE <6103677+fralken@users.noreply.github.com>}"
summary="Authenticating proxy for corporate proxies (NTLM, Kerberos)"

stage="$PWD/dist/stage/gatir-${version}-${target}"
[ -x "$stage/gatir" ] || { echo "run scripts/package.sh ${target} first" >&2; exit 1; }

checksum() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd dist && sha256sum "$(basename "$file")" > "$(basename "$file").sha256")
  else
    (cd dist && shasum -a 256 "$(basename "$file")" > "$(basename "$file").sha256")
  fi
}

# ---- the files of the package, as they are put on the system ----

# Puts the program and its documentation under $1, as a package installs them.
lay_out() {
  local root="$1" doc="$1/usr/share/doc/gatir"
  install -Dm755 "$stage/gatir" "$root/usr/bin/gatir"
  install -Dm644 "$stage/README.md" "$doc/README.md"
  install -Dm644 "$stage/gatir.example.toml" "$doc/examples/gatir.example.toml"
  install -Dm644 "$stage/LICENSE-MIT" "$doc/LICENSE-MIT"
  install -Dm644 "$stage/LICENSE-APACHE" "$doc/LICENSE-APACHE"
  local page
  for page in "$stage"/docs/*.md; do
    install -Dm644 "$page" "$doc/docs/$(basename "$page")"
  done
  # The manual pages, compressed as Debian and Fedora keep them.
  for page in "$stage"/man/man1/*.1; do
    install -dm755 "$root/usr/share/man/man1"
    gzip -9n -c "$page" > "$root/usr/share/man/man1/$(basename "$page").gz"
    chmod 644 "$root/usr/share/man/man1/$(basename "$page").gz"
  done
}

# ---- .deb ----

deb_root="$PWD/dist/stage/deb-${version}-${deb_arch}"
rm -rf "$deb_root"
lay_out "$deb_root"

# The licenses, in the form Debian reads.
{
  echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
  echo "Upstream-Name: gatir"
  echo
  echo "Files: *"
  echo "Copyright: 2026 The gatir contributors"
  echo "License: MIT or Apache-2.0"
  echo
  echo "License: MIT"
  sed 's/^$/./; s/^/ /' LICENSE-MIT
  echo
  echo "License: Apache-2.0"
  echo " On Debian systems, the full text of the Apache License 2.0 is in"
  echo " /usr/share/common-licenses/Apache-2.0."
} > "$deb_root/usr/share/doc/gatir/copyright"
chmod 644 "$deb_root/usr/share/doc/gatir/copyright"

# The changelog that Debian expects of a package that is not made by its authors
# for Debian alone: one entry, the release.
printf 'gatir (%s-1) unstable; urgency=medium\n\n  * Release %s.\n\n -- %s  %s\n' \
  "$version" "$version" "$maintainer" "$(date -u -R)" \
  | gzip -9n > "$deb_root/usr/share/doc/gatir/changelog.Debian.gz"
chmod 644 "$deb_root/usr/share/doc/gatir/changelog.Debian.gz"

# What the program needs, from the libraries it is linked to. (The tool warns
# that the program is not where a package keeps it; that is of no consequence
# here, and its messages are shown only if it finds nothing.)
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/debian"
printf 'Source: gatir\n\nPackage: gatir\nArchitecture: any\n' > "$work/debian/control"
depends="$(cd "$work" && dpkg-shlibdeps -O -e "$deb_root/usr/bin/gatir" 2> "$work/shlibdeps.log" \
  | sed -n 's/^shlibs:Depends=//p')"
[ -n "$depends" ] || { cat "$work/shlibdeps.log" >&2; echo "dpkg-shlibdeps found no dependencies" >&2; exit 1; }

mkdir -p "$deb_root/DEBIAN"
(cd "$deb_root" && find usr -type f -exec md5sum {} + | sort -k 2 > DEBIAN/md5sums)
cat > "$deb_root/DEBIAN/control" <<CONTROL
Package: gatir
Version: ${version}-1
Architecture: ${deb_arch}
Maintainer: ${maintainer}
Installed-Size: $(du -sk "$deb_root/usr" | cut -f1)
Depends: ${depends}
Recommends: libgssapi-krb5-2
Section: net
Priority: optional
Description: ${summary}
 gatir is a local proxy that logs in to the proxy of a company for programs that
 cannot do NTLM or Kerberos themselves. It can choose the proxy for each request
 with a PAC script, and also serves SOCKS5 and forwards local ports.
CONTROL

deb="dist/gatir_${version}-1_${deb_arch}.deb"
rm -f "$deb" "$deb.sha256"
dpkg-deb --root-owner-group --build "$deb_root" "$deb" > /dev/null
checksum "$deb"

# ---- .rpm ----

top="$PWD/dist/stage/rpm-${version}-${rpm_arch}"
rm -rf "$top"
mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cat > "$top/SPECS/gatir.spec" <<SPEC
# The program is stripped already, and rpm has nothing to add.
%global debug_package %{nil}
%global __os_install_post %{nil}

Name:     gatir
Version:  ${version}
Release:  1
Summary:  ${summary}
License:  MIT OR Apache-2.0
Packager: ${maintainer}
Recommends: krb5-libs

%description
gatir is a local proxy that logs in to the proxy of a company for programs that
cannot do NTLM or Kerberos themselves. It can choose the proxy for each request
with a PAC script, and also serves SOCKS5 and forwards local ports.

%install
install -Dm755 ${stage}/gatir %{buildroot}/usr/bin/gatir
install -Dm644 ${stage}/README.md %{buildroot}%{_docdir}/gatir/README.md
install -Dm644 ${stage}/gatir.example.toml %{buildroot}%{_docdir}/gatir/examples/gatir.example.toml
install -Dm644 ${stage}/LICENSE-MIT %{buildroot}%{_licensedir}/gatir/LICENSE-MIT
install -Dm644 ${stage}/LICENSE-APACHE %{buildroot}%{_licensedir}/gatir/LICENSE-APACHE
for page in ${stage}/docs/*.md; do
  install -Dm644 "\$page" "%{buildroot}%{_docdir}/gatir/docs/\$(basename "\$page")"
done
for page in ${stage}/man/man1/*.1; do
  install -dm755 %{buildroot}%{_mandir}/man1
  gzip -9n -c "\$page" > "%{buildroot}%{_mandir}/man1/\$(basename "\$page").gz"
  chmod 644 "%{buildroot}%{_mandir}/man1/\$(basename "\$page").gz"
done

%files
/usr/bin/gatir
%license %{_licensedir}/gatir/LICENSE-MIT
%license %{_licensedir}/gatir/LICENSE-APACHE
%{_docdir}/gatir
%{_mandir}/man1/gatir*.1.gz
SPEC
# gzip in the payload, so that older versions of rpm can read the package.
rpmbuild -bb --quiet --target "${rpm_arch}-linux" \
  --define "_topdir ${top}" --define "_binary_payload w9.gzdio" \
  --define "_build_id_links none" \
  "$top/SPECS/gatir.spec"
rpm="dist/gatir-${version}-1.${rpm_arch}.rpm"
rm -f "$rpm" "$rpm.sha256"
cp "$top/RPMS/${rpm_arch}/gatir-${version}-1.${rpm_arch}.rpm" "$rpm"
checksum "$rpm"

echo "$deb"
cat "$deb.sha256"
echo "$rpm"
cat "$rpm.sha256"
