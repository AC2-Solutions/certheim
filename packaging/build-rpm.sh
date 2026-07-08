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

echo "=== nfpm package ==="
export PKG_VERSION PKG_ARCH
nfpm package --config packaging/nfpm.yaml --packager rpm --target packaging/build/
ls -la packaging/build/*.rpm
echo "=== done: $(ls packaging/build/*.rpm) ==="
