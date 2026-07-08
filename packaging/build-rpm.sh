#!/bin/bash
# build-rpm.sh — build the Certheim .rpm with nfpm.
#
# Stages the application/installer tree + an offline Python wheelhouse under
# packaging/build/stage, then runs nfpm against packaging/nfpm.yaml.
#
#   PKG_VERSION   package version   (default: editions/community.version)
#   PKG_ARCH      nfpm arch         (default: amd64 -> rpm x86_64)
#   PYBIN         python for the wheelhouse (default: python3, must be >=3.9)
#
# Requires: nfpm on PATH, python3 with pip + internet (to fetch the wheels).
# Output: packaging/build/certheim_<version>_<arch>.rpm
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

PKG_VERSION="${PKG_VERSION:-$(cat editions/community.version 2>/dev/null || cat VERSION 2>/dev/null || echo 0.0.0)}"
PKG_ARCH="${PKG_ARCH:-amd64}"
PYBIN="${PYBIN:-python3}"
STAGE="packaging/build/stage"
DEST="$STAGE/usr/share/certheim"

echo "=== staging Certheim v$PKG_VERSION ($PKG_ARCH) ==="
rm -rf packaging/build
mkdir -p "$DEST" "$STAGE/usr/sbin" "$STAGE/usr/share/doc/certheim"

# Materialize the community edition version into VERSION for the packaged tree
# (each branch keeps its number in editions/<edition>.version).
cp -f editions/community.version VERSION 2>/dev/null || true

# The app/installer tree online-install.sh + deploy.sh need at runtime.
for item in VERSION deploy.sh verify.sh README.md requirements.txt requirements-postgres.txt \
            backend frontend helper systemd nginx tools config docs install editions; do
    if [[ -e "$item" ]]; then cp -r "$item" "$DEST/"; else echo "  (skip missing: $item)"; fi
done

# Offline wheelhouse: pure-Python base deps resolve to universal (py3-none-any)
# wheels, so one wheelhouse installs on any target python 3.9-3.13. psycopg
# (postgres) is intentionally excluded to keep the package slim — the installer
# fetches it on demand when DB_BACKEND=postgres.
echo "=== building wheelhouse with $PYBIN ==="
command -v "$PYBIN" >/dev/null || { echo "ERROR: $PYBIN not found" >&2; exit 1; }
mkdir -p "$DEST/wheelhouse"
"$PYBIN" -m pip download -q -d "$DEST/wheelhouse" pip setuptools wheel
"$PYBIN" -m pip download -q -d "$DEST/wheelhouse" -r requirements.txt
echo "  wheels: $(ls "$DEST/wheelhouse" | wc -l)"

install -m 0755 packaging/certheim-setup "$STAGE/usr/sbin/certheim-setup"
install -m 0644 packaging/README.rpm.md  "$STAGE/usr/share/doc/certheim/README.md"
# Ship the public signing key alongside the app too (for reference / re-import).
install -m 0644 packaging/RPM-GPG-KEY-certheim "$STAGE/usr/share/doc/certheim/RPM-GPG-KEY-certheim"

# GPG-sign the RPM when a signing key is provided (CI on tagged releases), so it
# installs on STIG / gpgcheck-enforced hosts. CERTHEIM_RPM_SIGN_KEY_FILE points
# at the armored private key; CERTHEIM_RPM_SIGN_PASSPHRASE holds its passphrase.
# Absent (local dev builds) → unsigned, as before. nfpm signs natively (no
# rpm-sign package needed). The matching public key is packaging/RPM-GPG-KEY-certheim.
NFPM_CONFIG=packaging/nfpm.yaml
if [[ -n "${CERTHEIM_RPM_SIGN_KEY_FILE:-}" && -r "${CERTHEIM_RPM_SIGN_KEY_FILE}" ]]; then
    echo "=== signing enabled (key: $CERTHEIM_RPM_SIGN_KEY_FILE) ==="
    NFPM_CONFIG=packaging/build/nfpm-signed.yaml
    awk -v key="$CERTHEIM_RPM_SIGN_KEY_FILE" '
        {print}
        /^  compression: gzip$/ { print "  signature:"; print "    key_file: " key }
    ' packaging/nfpm.yaml > "$NFPM_CONFIG"
    export NFPM_RPM_PASSPHRASE="${CERTHEIM_RPM_SIGN_PASSPHRASE:-}"
else
    echo "=== signing disabled (CERTHEIM_RPM_SIGN_KEY_FILE unset) — building UNSIGNED ==="
fi

echo "=== nfpm package ==="
export PKG_VERSION PKG_ARCH
nfpm package --config "$NFPM_CONFIG" --packager rpm --target packaging/build/
ls -la packaging/build/*.rpm
# Surface the signature state so CI logs make it obvious.
rpm -qpi packaging/build/*.rpm 2>/dev/null | grep -i "^Signature" || true
echo "=== done: $(ls packaging/build/*.rpm) ==="
