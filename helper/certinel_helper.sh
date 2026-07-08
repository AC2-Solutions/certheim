#!/bin/bash
# certinel_helper.sh - mediated root operations for the CSR dashboard
#
# This is the dispatcher. All implementation lives in numbered parts under
# certinel_helper.d/ in the same directory, sourced in lexical order:
#   00-common.sh     paths, audit, generic file operations
#   10-certtypes.sh  cert type profiles, combination + SAN logic
#   20-generate.sh   generate_typed pipeline
#
# SECURITY: every part sourced here must be owned by the user the helper runs
# as (root via sudo on a VM; the unprivileged service user in container mode -
# CERTINEL_CONTAINER=1, where the helper runs sudo-less) and never be
# group/world-writable. Crossing no privilege boundary, owner == euid is as safe
# as owner == root, and on a VM euid is 0 so root is still required there.
set -euo pipefail

HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_D="$HELPER_DIR/certinel_helper.d"

if [[ ! -d "$HELPER_D" ]]; then
    echo "ERROR: $HELPER_D not found - helper is not fully installed" >&2
    exit 70
fi

# Refuse to source anything writable by group/other, or not owned by root or the
# user running the helper (euid). The latter covers sudo-less container mode,
# where parts are owned by the unprivileged service user, not root.
self_uid="$(id -u)"
for part in "$HELPER_D"/*.sh; do
    [[ -e "$part" ]] || { echo "ERROR: no parts in $HELPER_D" >&2; exit 70; }
    perms=$(stat -c '%u %U %a' "$part")
    ouid="${perms%% *}"; rest="${perms#* }"; owner="${rest%% *}"; mode="${rest##* }"
    if [[ ( "$ouid" != "0" && "$ouid" != "$self_uid" ) \
          || "${mode: -2:1}" =~ [2367] || "${mode: -1}" =~ [2367] ]]; then
        echo "ERROR: refusing to source $part (owner=$owner mode=$mode)" >&2
        exit 71
    fi
    # shellcheck source=/dev/null
    source "$part"
done

cmd="${1:-}"
shift || true
audit "invoke caller=${SUDO_USER:-?} cmd=${cmd:-?} arg=${1:-}"

case "$cmd" in
    read-certlist-rhel)
        read_certlist "$CERTLIST_RHEL"
        ;;
    write-certlist-rhel)
        write_certlist "$CERTLIST_RHEL"
        ;;
    read-subject)
        read_subject
        ;;
    write-subject)
        write_subject "${1:-}"
        ;;
    delete-subject-profile)
        delete_subject_profile "${1:-}"
        ;;
    generate-rhel)
        # Legacy: defers to csr-rhel.sh (web certs only). Kept for external
        # scripts. The dashboard uses generate-typed.
        audit "generate-rhel start"
        bash "$GEN_RHEL"
        rc=$?
        audit "generate-rhel end rc=$rc"
        exit $rc
        ;;
    generate-typed)
        generate_typed "${1:-}" "${2:-rsa2048}" "${3:-}" "${4:-}"
        ;;
    list-csrs)
        list_files "$CSRDIR" '*.csr'
        ;;
    get-csr)
        cat_file "$CSRDIR" '^[A-Za-z0-9._-]+\.csr$' "${1:-}"
        ;;
    delete-csr)
        delete_file "$CSRDIR" '^[A-Za-z0-9._-]+\.csr$' "${1:-}"
        ;;
    list-keys)
        list_files "$KEYDIR" '*.key'
        ;;
    get-key)
        cat_file "$KEYDIR" '^[A-Za-z0-9._-]+\.key$' "${1:-}"
        ;;
    delete-key)
        delete_file "$KEYDIR" '^[A-Za-z0-9._-]+\.key$' "${1:-}"
        ;;
    chown-issued)
        fname="${1:-}"
        if [[ ! "$fname" =~ ^[A-Za-z0-9._-]+\.cer$ ]]; then
            audit "$cmd deny invalid_name"
            echo "ERROR: invalid filename" >&2
            exit 2
        fi
        target="$ISSUED_DIR/$fname"
        if [[ -f "$target" ]]; then
            { [ "$(id -u)" = "0" ] && id ansible >/dev/null 2>&1 && chown ansible:ansible "$target"; } || true
            chmod 0644 "$target"
            audit "$cmd ok name=$fname"
        fi
        ;;
    delete-issued)
        delete_file "$ISSUED_DIR" '^[A-Za-z0-9._-]+\.cer$' "${1:-}"
        ;;
    install-ca-bundle)
        # Install the Certheim CA trust bundle (PEM on stdin) into this host.
        install_ca_bundle
        ;;
    apply-mtls)
        # Render the app-managed nginx client-cert (mTLS) fragment + reload.
        apply_mtls "${1:-off}" "${2:-}"
        ;;
    *)
        cat >&2 <<EOF
Usage: $0 <subcommand> [args]

  read-certlist-rhel
  write-certlist-rhel               (reads stdin)
  generate-rhel                     (legacy: csr-rhel.sh, web only)
  generate-typed <types> [algo]     types comma-separated, e.g. "web,client"
                                    algo: rsa2048 (default) | rsa3072 |
                                          rsa4096 | ecdsa256 | ecdsa384
                                    types: web client email codesign ipsec
                                           ocsp timestamp 8021x
                                    (codesign/ocsp/timestamp cannot combine)
  list-csrs / get-csr / delete-csr <name>
  list-keys / get-key / delete-key <name>
  chown-issued / delete-issued <name>
  install-ca-bundle                 (reads PEM CA bundle on stdin)
  apply-mtls <enforce|optional|off> [client-ca-bundle-path]
EOF
        exit 64
        ;;
esac
