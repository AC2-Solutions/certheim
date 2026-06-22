#!/bin/bash
# 20-generate.sh - the generate_typed pipeline: read certlist, validate each
# CN against the requested type combo, build per-entry openssl config,
# generate key+CSR. Sourced by certinel_helper.sh.

generate_typed() {
    local types_input="${1:-}"
    local key_algo="${2:-rsa2048}"
    local domain_choice="${3:-}"
    if [[ -z "$types_input" ]]; then
        echo "ERROR: cert type(s) required, e.g. 'web' or 'web,client'" >&2
        return 2
    fi
    # Per-batch domain-suffix choice (validated against the admin allow-list;
    # a non-listed value is ignored). Overrides DOMAIN_SUFFIX for this run, so
    # fqdn_qualify uses it for bare hostnames.
    apply_domain_choice "$domain_choice"
    if [[ ! "$key_algo" =~ ^(rsa2048|rsa3072|rsa4096|ecdsa256|ecdsa384)$ ]]; then
        echo "ERROR: invalid key_algo (rsa2048|rsa3072|rsa4096|ecdsa256|ecdsa384)" >&2
        return 2
    fi

    # openssl -newkey arguments per algorithm
    local newkey_args=()
    case "$key_algo" in
        rsa2048)  newkey_args=(-newkey rsa:2048) ;;
        rsa3072)  newkey_args=(-newkey rsa:3072) ;;
        rsa4096)  newkey_args=(-newkey rsa:4096) ;;
        ecdsa256) newkey_args=(-newkey ec -pkeyopt ec_paramgen_curve:prime256v1) ;;
        ecdsa384) newkey_args=(-newkey ec -pkeyopt ec_paramgen_curve:secp384r1) ;;
    esac

    local types_csv
    if ! types_csv=$(normalize_types "$types_input"); then
        return 2
    fi

    if [[ ! -f "$CERTLIST_RHEL" ]]; then
        echo "ERROR: certlist not found at $CERTLIST_RHEL" >&2
        return 1
    fi

    mkdir -p "$CSRDIR" "$KEYDIR"

    local config_file
    config_file=$(mktemp /tmp/csr-config-XXXXXX.cnf)
    # shellcheck disable=SC2064
    trap "rm -f '$config_file'" RETURN

    local count=0 failed=0 line_no=0
    audit "generate-typed start types=$types_csv algo=$key_algo"

    local line cn sans_part safe_name key_file csr_file
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_no=$((line_no + 1))
        line="${line//$'\r'/}"
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        cn="${line%%,*}"
        sans_part=""
        [[ "$line" == *,* ]] && sans_part="${line#*,}"

        # Domain-qualify bare short names ("test" -> "test.example.com"),
        # matching the legacy csr-rhel.sh behavior. IPs/emails untouched.
        cn=$(fqdn_qualify "$cn")

        if ! validate_cn_for_types "$types_csv" "$cn"; then
            echo "SKIP: line $line_no: invalid CN '$cn' for types $types_csv" >&2
            failed=$((failed + 1))
            continue
        fi

        build_csr_config_multi "$types_csv" "$cn" "$sans_part" > "$config_file"

        safe_name=$(filename_safe "$cn")
        key_file="$KEYDIR/${safe_name}.key"
        csr_file="$CSRDIR/${safe_name}.csr"

        if openssl req -new "${newkey_args[@]}" -nodes -batch \
                -keyout "$key_file" -out "$csr_file" \
                -config "$config_file" >/dev/null 2>&1; then
            chmod 0600 "$key_file"
            chown root:root "$key_file"
            chmod 0644 "$csr_file"
            chown root:root "$csr_file"
            count=$((count + 1))
            echo "OK: [$types_csv/$key_algo] CSR generated for ${cn} -> ${safe_name}.csr"
        else
            failed=$((failed + 1))
            rm -f "$key_file" "$csr_file"
            echo "ERROR: openssl failed for ${cn}" >&2
        fi
    done < "$CERTLIST_RHEL"

    audit "generate-typed end types=$types_csv algo=$key_algo count=$count failed=$failed"
    echo "DONE: ${count} CSR(s) generated, ${failed} failed (types=${types_csv})"
    [[ $count -gt 0 ]] && return 0 || return 1
}
