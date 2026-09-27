#!/usr/bin/env bash
# Makes an .msi of a Windows build that scripts/package.sh has already packed,
# into dist/, next to a .sha256 file. It installs gatir.exe under Program Files,
# adds that folder to the PATH, and removes both on uninstall; installing a new
# version over an old one removes the old one first (a major upgrade). There is
# no wizard: msiexec shows its own progress dialog, and /quiet works for an
# unattended install.
#
#   scripts/package-windows.sh [TARGET]    TARGET is x86_64-pc-windows-msvc,
#                                          x86_64-pc-windows-gnu or
#                                          aarch64-pc-windows-msvc; the default
#                                          is this machine's.
#
# It needs wixl, from msitools (`brew install msitools`, `apt-get install
# msitools`): a build of the .msi format that does not need Windows or WiX
# itself, so this runs wherever gatir is built. GATIR_MANUFACTURER sets the
# manufacturer named in the package.
set -euo pipefail

cd "$(dirname "$0")/.."

target="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
case "$target" in
  x86_64-pc-windows-msvc | x86_64-pc-windows-gnu) arch=x64 ;;
  aarch64-pc-windows-msvc) arch=arm64 ;;
  *) echo "an .msi is made for Windows targets only, not ${target}" >&2; exit 1 ;;
esac
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
manufacturer="${GATIR_MANUFACTURER:-The gatir contributors}"

stage="$PWD/dist/stage/gatir-${version}-${target}"
[ -f "$stage/gatir.exe" ] || { echo "run scripts/package.sh ${target} first" >&2; exit 1; }
command -v wixl >/dev/null 2>&1 || { echo "wixl is not installed (see the top of this script)" >&2; exit 1; }

# Fixed identifiers of the package. UPGRADE_CODE names gatir across every
# version, and must never change: it is how Windows Installer finds the old
# version to remove when a newer one is installed. The others each name one
# group of files that is installed or removed together; they may be reused for
# a group whose files change from one release to the next; because a major
# upgrade always removes the old version first (below), a stale one left behind
# by an in-place upgrade is not a concern here.
UPGRADE_CODE="AAB56D5C-4958-4FC2-8A91-57AAA1F33222"
PROGRAM_GUID="DCC5AAB2-9F99-4930-B62C-32C13683CA10"
DOCUMENTATION_GUID="30815F8F-211E-4952-988E-CE9C2CCF52C5"
DOCS_GUID="E13C78DC-A930-4983-8530-64E533C8A188"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# One <File> per documentation page, generated here so that adding a page to
# docs/ needs no change to this script.
docs_files=""
for page in "$stage"/docs/*.md; do
  id="Doc_$(basename "$page" .md | tr -c 'A-Za-z0-9' _)"
  docs_files+="        <File Id=\"${id}\" Name=\"$(basename "$page")\" Source=\"${page}\" />"$'\n'
done

cat > "$work/gatir.wxs" <<WXS
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="gatir" Language="1033" Version="${version}"
           Manufacturer="${manufacturer}" UpgradeCode="${UPGRADE_CODE}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine"
              Description="gatir ${version}"
              Comments="Authenticating proxy for corporate proxies (NTLM, Kerberos)" />
    <MajorUpgrade DowngradeErrorMessage="A newer version of gatir is already installed." />
    <MediaTemplate EmbedCab="yes" />

    <!-- Nothing to modify once it is installed: only repair or remove. -->
    <Property Id="ARPNOMODIFY" Value="1" />

    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLFOLDER" Name="gatir">
          <Directory Id="DocsFolder" Name="docs" />
        </Directory>
      </Directory>
    </Directory>

    <DirectoryRef Id="INSTALLFOLDER">
      <Component Id="Program" Guid="${PROGRAM_GUID}">
        <File Id="GatirExe" Name="gatir.exe" Source="${stage}/gatir.exe" KeyPath="yes" />
        <!-- Added when gatir is installed, and only that one entry removed
             when it is not: nothing else on the PATH is touched. -->
        <Environment Id="Path" Name="PATH" Value="[INSTALLFOLDER]" Permanent="no"
                     Part="last" Action="set" System="yes" />
      </Component>
      <Component Id="Documentation" Guid="${DOCUMENTATION_GUID}">
        <File Id="Readme" Name="README.md" Source="${stage}/README.md" KeyPath="yes" />
        <File Id="LicenseMit" Name="LICENSE-MIT" Source="${stage}/LICENSE-MIT" />
        <File Id="LicenseApache" Name="LICENSE-APACHE" Source="${stage}/LICENSE-APACHE" />
        <File Id="ExampleConfig" Name="gatir.example.toml" Source="${stage}/gatir.example.toml" />
      </Component>
    </DirectoryRef>
    <DirectoryRef Id="DocsFolder">
      <Component Id="Docs" Guid="${DOCS_GUID}">
${docs_files}      </Component>
    </DirectoryRef>

    <Feature Id="Complete" Title="gatir" Level="1">
      <ComponentRef Id="Program" />
      <ComponentRef Id="Documentation" />
      <ComponentRef Id="Docs" />
    </Feature>
  </Product>
</Wix>
WXS

name="gatir-${version}-${arch}"
rm -f "dist/${name}.msi" "dist/${name}.msi.sha256"
wixl -a "$arch" -o "dist/${name}.msi" "$work/gatir.wxs"

if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum "${name}.msi" > "${name}.msi.sha256")
else
  (cd dist && shasum -a 256 "${name}.msi" > "${name}.msi.sha256")
fi

echo "dist/${name}.msi"
cat "dist/${name}.msi.sha256"
