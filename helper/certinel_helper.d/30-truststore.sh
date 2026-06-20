#!/bin/bash
# 30-truststore.sh - install the Certinel CA trust bundle into THIS host's OS
# trust store. Sourced by certinel_helper.sh; never executed directly.
#
# install_ca_bundle reads a PEM bundle (one or more CA certs) on stdin and adds
# it to the host trust anchors, auto-detecting the platform tool:
#   RHEL-family : /etc/pki/ca-trust/source/anchors + update-ca-trust extract
#   Debian-family: split per-cert into /usr/local/share/ca-certificates +
#                  update-ca-certificates
# Only CA certificates belong here; the app validates that before calling us.

TRUST_ANCHOR_NAME="certinel-trust-bundle.crt"

install_ca_bundle() {
    local tmp
    tmp="$(mktemp /tmp/certinel-trust.XXXXXX)"
    # Cap the input and require at least one PEM cert block.
    head -c 1048576 > "$tmp"
    if ! grep -q "BEGIN CERTIFICATE" "$tmp"; then
        rm -f "$tmp"
        audit "install_ca_bundle deny no_cert"
        echo "ERROR: no certificate in input" >&2
        exit 2
    fi
    if command -v update-ca-trust >/dev/null 2>&1; then
        install -m 0644 -o root -g root "$tmp" \
            "/etc/pki/ca-trust/source/anchors/$TRUST_ANCHOR_NAME"
        rm -f "$tmp"
        update-ca-trust extract
        audit "install_ca_bundle ok tool=update-ca-trust"
        echo "installed via update-ca-trust"
    elif command -v update-ca-certificates >/dev/null 2>&1; then
        rm -f /usr/local/share/ca-certificates/certinel-trust-*.crt
        awk '/BEGIN CERT/{n++} {print > ("/usr/local/share/ca-certificates/certinel-trust-" n ".crt")}' "$tmp"
        rm -f "$tmp"
        update-ca-certificates
        audit "install_ca_bundle ok tool=update-ca-certificates"
        echo "installed via update-ca-certificates"
    else
        rm -f "$tmp"
        audit "install_ca_bundle deny no_tool"
        echo "ERROR: no supported trust tool (update-ca-trust/update-ca-certificates)" >&2
        exit 3
    fi
}
