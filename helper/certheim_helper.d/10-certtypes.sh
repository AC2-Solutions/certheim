#!/bin/bash
# 10-certtypes.sh - cert type profiles, combination rules, SAN handling,
# and openssl config generation. Sourced by certheim_helper.sh.
#
# Type model:
#   Combinable: web client email ipsec 8021x   (EKUs union into one cert)
#   Exclusive : codesign ocsp timestamp        (must be requested alone)
#   Legacy    : "server-client" accepted as an alias for "client,web"

CERT_TYPE_LIST="web client email codesign ipsec ocsp timestamp 8021x"
EXCLUSIVE_TYPES="codesign ocsp timestamp"

type_is_known()     { [[ " $CERT_TYPE_LIST " == *" $1 "* ]]; }
type_is_exclusive() { [[ " $EXCLUSIVE_TYPES " == *" $1 "* ]]; }

# normalize_types <csv>
# Validates, expands the server-client alias, dedupes, sorts, enforces
# exclusivity. Echoes canonical csv (e.g. "client,web"). Returns 2 on error.
normalize_types() {
    local csv="${1:-}"
    local -A seen=()
    local out=()
    local IFS=','
    local parts=()
    read -ra parts <<< "$csv"
    local p q
    for p in "${parts[@]}"; do
        p="${p//[[:space:]]/}"
        [[ -z "$p" ]] && continue
        if [[ "$p" == "server-client" ]]; then
            for q in client web; do
                [[ -n "${seen[$q]:-}" ]] || { seen[$q]=1; out+=("$q"); }
            done
            continue
        fi
        if ! type_is_known "$p"; then
            echo "ERROR: unknown cert type '$p'" >&2
            return 2
        fi
        [[ -n "${seen[$p]:-}" ]] || { seen[$p]=1; out+=("$p"); }
    done
    if [[ ${#out[@]} -eq 0 ]]; then
        echo "ERROR: no cert types given" >&2
        return 2
    fi
    if [[ ${#out[@]} -gt 1 ]]; then
        for p in "${out[@]}"; do
            if type_is_exclusive "$p"; then
                echo "ERROR: type '$p' cannot be combined with other types" >&2
                return 2
            fi
        done
    fi
    local sorted
    sorted=$(printf '%s\n' "${out[@]}" | sort | paste -sd,)
    echo "$sorted"
}

# combo_needs_host_cn <csv> - true if any selected type identifies a host
combo_needs_host_cn() {
    local csv="$1" t
    local IFS=','
    for t in $csv; do
        case "$t" in
            web|ipsec|8021x|ocsp|timestamp|codesign) return 0 ;;
        esac
    done
    return 1
}

# validate_cn_for_types <csv> <cn>
validate_cn_for_types() {
    local csv="$1" cn="$2"
    if combo_needs_host_cn "$csv"; then
        [[ "$cn" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$ ]]
    else
        # client/email-only combos: hostname-style or RFC 5321 email
        [[ "$cn" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$ ]] || \
        [[ "$cn" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
    fi
}

# fqdn_qualify <name>
# Appends .$DOMAIN_SUFFIX to bare short names. Leaves alone: anything with a
# dot already, email addresses, IPv4/IPv6 literals, or when DOMAIN_SUFFIX
# is unset/empty.
fqdn_qualify() {
    local n="$1"
    if [[ -z "${DOMAIN_SUFFIX:-}" ]]; then
        echo "$n"; return 0
    fi
    if [[ "$n" == *.* || "$n" == *@* || "$n" == *:* ]]; then
        echo "$n"; return 0
    fi
    echo "${n}.${DOMAIN_SUFFIX}"
}

# Classify a single SAN entry: IPv4, IPv6 (contains ':'), email, or DNS.
# DNS entries get domain-qualified if they're bare short names.
san_entry() {
    local s="$1"
    if [[ "$s" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "IP:$s"
    elif [[ "$s" == *:* ]]; then
        echo "IP:$s"
    elif [[ "$s" =~ @ ]]; then
        echo "email:$s"
    else
        echo "DNS:$(fqdn_qualify "$s")"
    fi
}

# build_sans_host <cn> <sans_csv> - CN always included, all entries classified
build_sans_host() {
    local cn="$1"; local sans_raw="$2"
    local result; result=$(san_entry "$cn")
    if [[ -n "$sans_raw" ]]; then
        local IFS=','
        local arr=()
        read -ra arr <<< "$sans_raw"
        local s
        for s in "${arr[@]}"; do
            s=$(echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [[ -n "$s" && "$s" != "$cn" ]] && result+=",$(san_entry "$s")"
        done
    fi
    # Admin-configured extra SANs added to every cert.
    local _x
    for _x in "${SUBJECT_XSANS[@]}"; do
        [[ -n "$_x" && "$_x" != "$cn" ]] && result+=",$(san_entry "$_x")"
    done
    echo "$result"
}

# build_sans_smart <cn> <sans_csv> - CN only when it's an email; may be empty
build_sans_smart() {
    local cn="$1"; local sans_raw="$2"
    local parts=()
    if [[ "$cn" =~ @ ]]; then
        parts+=("email:$cn")
    fi
    if [[ -n "$sans_raw" ]]; then
        local IFS=','
        local arr=()
        read -ra arr <<< "$sans_raw"
        local s
        for s in "${arr[@]}"; do
            s=$(echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [[ -z "$s" ]] && continue
            parts+=("$(san_entry "$s")")
        done
    fi
    # Admin-configured extra SANs added to every cert.
    local _x
    for _x in "${SUBJECT_XSANS[@]}"; do
        [[ -n "$_x" ]] && parts+=("$(san_entry "$_x")")
    done
    if [[ ${#parts[@]} -eq 0 ]]; then
        return 0
    fi
    local IFS=','; echo "${parts[*]}"
}

# build_csr_config_multi <types_csv> <cn> <sans_csv>
# Emits a complete openssl req config with merged KU/EKU/SAN for the combo.
build_csr_config_multi() {
    local types_csv="$1"; local cn="$2"; local sans_raw="$3"

    local key_encipherment="no"
    local eku_critical="no"
    local san_strategy="none"   # none < smart < host (priority)
    local eku_list=()
    local -A eku_seen=()

    add_eku() {
        local e="$1"
        [[ -n "${eku_seen[$e]:-}" ]] || { eku_seen[$e]=1; eku_list+=("$e"); }
    }
    raise_san() {
        # only upgrade: none->smart, none/smart->host
        local want="$1"
        if [[ "$want" == "host" ]]; then
            san_strategy="host"
        elif [[ "$want" == "smart" && "$san_strategy" == "none" ]]; then
            san_strategy="smart"
        fi
    }

    local t
    local IFS=','
    for t in $types_csv; do
        case "$t" in
            web)
                key_encipherment="yes"
                add_eku "serverAuth"
                raise_san host
                ;;
            client)
                add_eku "clientAuth"
                raise_san smart
                ;;
            email)
                key_encipherment="yes"
                add_eku "emailProtection"
                raise_san smart
                ;;
            ipsec)
                key_encipherment="yes"
                add_eku "1.3.6.1.5.5.7.3.17"
                raise_san host
                ;;
            8021x)
                add_eku "clientAuth"
                add_eku "1.3.6.1.5.5.7.3.14"
                raise_san host
                ;;
            codesign)
                add_eku "codeSigning"
                ;;
            ocsp)
                add_eku "OCSPSigning"
                raise_san host
                ;;
            timestamp)
                # RFC 3161: EKU critical, ONLY timeStamping (exclusive type)
                add_eku "timeStamping"
                eku_critical="yes"
                raise_san host
                ;;
        esac
    done
    unset IFS

    cat <<EOF
[req]
distinguished_name = req_dn
req_extensions     = v3_ext
prompt             = no

[req_dn]
EOF

    # Full organizational subject DN (configured via the admin UI -> subject.conf,
    # falling back to 00-common.sh defaults), CN last.
    # Repeated OUs need numeric prefixes in openssl req config syntax.
    if [[ -n "${SUBJECT_C:-}" ]];  then echo "C  = $SUBJECT_C";  fi
    if [[ -n "${SUBJECT_ST:-}" ]]; then echo "ST = $SUBJECT_ST"; fi
    if [[ -n "${SUBJECT_L:-}" ]];  then echo "L  = $SUBJECT_L";  fi
    if [[ -n "${SUBJECT_O:-}" ]];  then echo "O  = $SUBJECT_O";  fi
    local _i=0 _ou
    for _ou in "${SUBJECT_OUS[@]}"; do
        echo "${_i}.OU = $_ou"
        _i=$((_i + 1))
    done
    # Admin-configured custom DN attributes (XDN=field:value), e.g.
    # businessCategory, serialNumber, DC. A running numeric prefix keeps every
    # config key unique so repeats (multiple DC) are valid openssl req syntax.
    local _xdn _field _val
    for _xdn in "${SUBJECT_XDN[@]}"; do
        _field="${_xdn%%:*}"
        _val="${_xdn#*:}"
        [[ -n "$_field" && -n "$_val" ]] && { echo "${_i}.${_field} = $_val"; _i=$((_i + 1)); }
    done
    echo "CN = $cn"
    echo ""
    echo "[v3_ext]"

    if [[ "$key_encipherment" == "yes" ]]; then
        echo "keyUsage         = critical, digitalSignature, keyEncipherment"
    else
        echo "keyUsage         = critical, digitalSignature"
    fi

    local eku_joined
    eku_joined=$(IFS=', '; echo "${eku_list[*]}")
    # IFS first-char join gives "a,b"; we want "a, b" spacing for readability
    eku_joined=${eku_joined//,/, }
    if [[ "$eku_critical" == "yes" ]]; then
        echo "extendedKeyUsage = critical, $eku_joined"
    else
        echo "extendedKeyUsage = $eku_joined"
    fi

    case "$san_strategy" in
        host)
            echo "subjectAltName   = $(build_sans_host "$cn" "$sans_raw")"
            ;;
        smart)
            local s=""
            s=$(build_sans_smart "$cn" "$sans_raw") || true
            if [[ -n "$s" ]]; then
                echo "subjectAltName   = $s"
            fi
            ;;
        none)
            : # codesign-only: no SAN
            ;;
    esac
}
