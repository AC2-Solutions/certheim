#!/bin/bash
# 40-mtls.sh - render the app-managed nginx client-cert (mTLS) fragment from the
# admin UI's Authentication settings. Lives in the include dir alongside
# 30-csr.conf; a fresh install writes the server block WITHOUT mTLS so this
# fragment is the single source of truth for client-cert verification.
#
# nginx config is tested before reload and rolled back on failure, so a bad
# bundle/path can never take the site down.

MTLS_FRAGMENT="/etc/nginx/csr-dashboard.d/10-mtls.conf"

apply_mtls() {
    # args: mode(enforce|optional|off) [bundle_path]
    local mode="${1:-off}" bundle="${2:-}"
    case "$mode" in
        enforce|optional|off) ;;
        *) audit "apply_mtls deny bad_mode=$mode"
           echo "ERROR: mode must be enforce|optional|off" >&2; exit 2 ;;
    esac
    if [[ "$mode" == "enforce" ]]; then
        if [[ ! "$bundle" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
            audit "apply_mtls deny bad_path"
            echo "ERROR: client-CA bundle must be an absolute path" >&2; exit 2
        fi
        [[ -s "$bundle" ]] || { echo "ERROR: client-CA bundle not found or empty: $bundle" >&2; exit 3; }
        grep -q "BEGIN CERTIFICATE" "$bundle" 2>/dev/null \
            || { echo "ERROR: no certificate in $bundle" >&2; exit 3; }
    fi

    local tmp; tmp="$(mktemp)"
    case "$mode" in
        enforce)  printf '# managed by Certinel (Admin -> Authentication)\nssl_client_certificate %s;\nssl_verify_client on;\nssl_verify_depth 3;\n' "$bundle" > "$tmp" ;;
        optional) printf '# managed by Certinel (Admin -> Authentication)\nssl_verify_client optional_no_ca;\nssl_verify_depth 3;\n' > "$tmp" ;;
        off)      printf '# managed by Certinel (Admin -> Authentication): client certs disabled\n' > "$tmp" ;;
    esac

    # Install, test, reload - restoring the previous fragment if nginx rejects it.
    local bak=""
    [[ -f "$MTLS_FRAGMENT" ]] && { bak="$(mktemp)"; cp -p "$MTLS_FRAGMENT" "$bak"; }
    install -m 0644 -o root -g root "$tmp" "$MTLS_FRAGMENT"; rm -f "$tmp"
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx
        [[ -n "$bak" ]] && rm -f "$bak"
        audit "apply_mtls ok mode=$mode"
        echo "mtls applied: mode=$mode"
    else
        if [[ -n "$bak" ]]; then cp -p "$bak" "$MTLS_FRAGMENT"; rm -f "$bak"
        else rm -f "$MTLS_FRAGMENT"; fi
        nginx -t >/dev/null 2>&1 && systemctl reload nginx
        audit "apply_mtls FAIL nginx_test mode=$mode"
        echo "ERROR: nginx rejected the mTLS config and it was reverted. If the" >&2
        echo "       server block still sets ssl_verify_client, remove it - mTLS is" >&2
        echo "       app-managed now (this fragment)." >&2
        exit 4
    fi
}
