#!/bin/bash
# 00-common.sh - paths, audit logging, generic file operations.
# Sourced by csr_dashboard_helper.sh; never executed directly.

CERTLIST_RHEL="/root/sslcerts/scripts/certlist-rhel"
GEN_RHEL="/root/sslcerts/scripts/csr-rhel.sh"
CSRDIR="/home/ansible/new_request"
KEYDIR="/root/sslcerts/private"
ISSUED_DIR="/home/ansible/issued"

# ----- Subject DN applied to every generated CSR -----
# Rendered in this order, then CN last. Edit per enclave as needed.
# Leave SUBJECT_C / SUBJECT_O empty to omit them entirely.
SUBJECT_C="US"
SUBJECT_O="U.S. Government"
SUBJECT_OUS=("USEUCOM" "DOD" "USA")

# ----- Domain qualification -----
# Short names (no dot) in the certlist get this suffix appended, both as the
# CN and in DNS SANs: "test" -> "test.eucom.mil". Applies only to
# hostname-style entries, never to IPs or email addresses.
# Leave empty to disable qualification.
DOMAIN_SUFFIX="eucom.mil"

audit() { /usr/bin/logger -p authpriv.notice -t csr-dashboard-helper -- "$@"; }

read_certlist() {
    local path="$1"
    [[ -f "$path" ]] && cat "$path" || true
}

write_certlist() {
    local path="$1"
    local tmp
    tmp="$(mktemp "$(dirname "$path")/.$(basename "$path").XXXXXX")"
    tr -d '\r' > "$tmp"
    # Allow alphanumerics, dot, underscore, comma, dash, @ (email CNs),
    # + (email +alias), : (IPv6 SANs)
    if grep -nvE '^[A-Za-z0-9._,@+:-]*$' "$tmp" >&2; then
        rm -f "$tmp"
        audit "write_certlist deny invalid_chars"
        echo "ERROR: invalid characters in certlist" >&2
        exit 2
    fi
    install -m 0644 -o root -g root "$tmp" "$path"
    rm -f "$tmp"
    audit "write_certlist ok bytes=$(stat -c%s "$path")"
}

list_files() {
    local dir="$1"
    local pattern="$2"
    if [[ -d "$dir" ]]; then
        find "$dir" -maxdepth 1 -type f -name "$pattern" \
            -printf '%f\t%s\t%TY-%Tm-%Td %TH:%TM\t%T@\n' | sort -k3,3r
    fi
}

cat_file() {
    local dir="$1"
    local name_re="$2"
    local fname="${3:-}"
    if [[ ! "$fname" =~ $name_re ]]; then
        audit "cat_file deny invalid_name"
        echo "ERROR: invalid filename" >&2
        exit 2
    fi
    local target="$dir/$fname"
    [[ -f "$target" ]] || { echo "ERROR: not found" >&2; exit 3; }
    cat "$target"
}

delete_file() {
    local dir="$1"
    local name_re="$2"
    local fname="${3:-}"
    if [[ ! "$fname" =~ $name_re ]]; then
        audit "delete_file deny invalid_name"
        echo "ERROR: invalid filename" >&2
        exit 2
    fi
    local target="$dir/$fname"
    if [[ -f "$target" ]]; then
        rm -f "$target"
        audit "delete_file ok name=$fname"
    fi
}

# Sanitize a CN into a safe filename (@ and anything unusual -> _)
filename_safe() {
    echo "$1" | sed 's/[^A-Za-z0-9._-]/_/g'
}
