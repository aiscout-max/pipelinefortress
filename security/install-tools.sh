#!/usr/bin/env bash
# Install a pinned scanner release on a Linux x64 CI runner and verify it
# against the SHA-256 checksum file published with that release. Never pipe a
# remote install script into a shell.
#
# usage: security/install-tools.sh <gitleaks|trivy|syft|kind>
# versions come from the workflow env (GITLEAKS_VERSION, TRIVY_VERSION, ...)
set -euo pipefail

tool="$1"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

case "$tool" in
  gitleaks)
    v="${GITLEAKS_VERSION:?}"
    base="https://github.com/gitleaks/gitleaks/releases/download/v$v"
    asset="gitleaks_${v}_linux_x64.tar.gz"
    sums="gitleaks_${v}_checksums.txt" ;;
  trivy)
    v="${TRIVY_VERSION:?}"
    base="https://github.com/aquasecurity/trivy/releases/download/v$v"
    asset="trivy_${v}_Linux-64bit.tar.gz"
    sums="trivy_${v}_checksums.txt" ;;
  syft)
    v="${SYFT_VERSION:?}"
    base="https://github.com/anchore/syft/releases/download/v$v"
    asset="syft_${v}_linux_amd64.tar.gz"
    sums="syft_${v}_checksums.txt" ;;
  kind)
    v="${KIND_VERSION:?}"
    base="https://github.com/kubernetes-sigs/kind/releases/download/$v"
    asset="kind-linux-amd64"
    sums="kind-linux-amd64.sha256sum" ;;
  *)
    echo "unknown tool: $tool" >&2
    exit 2 ;;
esac

curl -fsSLO --retry 3 "$base/$asset"
curl -fsSLO --retry 3 "$base/$sums"
grep -E "[[:space:]]\*?${asset}\$" "$sums" | sha256sum --check --strict -

if [[ "$asset" == *.tar.gz ]]; then
  tar -xzf "$asset" "$tool"
else
  mv "$asset" "$tool"
fi
sudo install -m 0755 "$tool" "/usr/local/bin/$tool"
echo "installed $tool $v (checksum verified)"
