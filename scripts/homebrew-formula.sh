#!/usr/bin/env bash
# Prints the Homebrew formula for a release, on standard output: it installs the
# macOS archives of that release. The formula goes in a tap (a repository called
# homebrew-<name>, in its Formula directory); see docs/release.md.
#
#   scripts/homebrew-formula.sh REPOSITORY TAG SHA256SUMS
#
# REPOSITORY is "owner/name" on GitHub, TAG the release (v0.1.0), and SHA256SUMS
# the file of checksums the release workflow publishes.
set -euo pipefail

[ "$#" -eq 3 ] || { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
repository="$1"; tag="$2"; sums="$3"
version="${tag#v}"

# The checksum of the archive of a target, from the file of checksums.
sum_of() {
  local name="gatir-${version}-$1.tar.gz" sum
  sum="$(awk -v name="$name" '$2 == name { print $1 }' "$sums")"
  [ -n "$sum" ] || { echo "no checksum for ${name} in ${sums}" >&2; exit 1; }
  echo "$sum"
}
url_of() {
  echo "https://github.com/${repository}/releases/download/${tag}/gatir-${version}-$1.tar.gz"
}
arm="aarch64-apple-darwin"
intel="x86_64-apple-darwin"
# Worked out here, before anything is printed: a checksum that is missing must
# stop the script, and that cannot happen inside the text below.
arm_url="$(url_of "$arm")"
arm_sum="$(sum_of "$arm")"
intel_url="$(url_of "$intel")"
intel_sum="$(sum_of "$intel")"

cat <<FORMULA
class Gatir < Formula
  desc "Authenticating proxy for corporate proxies (NTLM, Kerberos)"
  homepage "https://github.com/${repository}"
  version "${version}"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on :macos

  on_arm do
    url "${arm_url}"
    sha256 "${arm_sum}"
  end

  on_intel do
    url "${intel_url}"
    sha256 "${intel_sum}"
  end

  def install
    bin.install "gatir"
    doc.install "README.md", "gatir.example.toml"
    doc.install Dir["docs/*"]
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/gatir --version")
  end
end
FORMULA
