#!/bin/bash
# 00-common.sh - paths, audit logging, generic file operations.
# Sourced by certinel_helper.sh; never executed directly.

# Certinel paths. The helper + its transient key scratch live off /root now
# (Phase 4b) so the systemd sandbox can mask /home + /root. Data under /var/opt,
# the helper under /opt; KEYDIR is a brief scratch (keys go to the vault).
CERTLIST_RHEL="/var/opt/certinel/certlist-rhel"
GEN_RHEL="/opt/certinel/helper/csr-rhel.sh"      # legacy generate-rhel (unused)
# Certinel data root (FHS /var/opt). Must match the app's CSR_ISSUED_DIR.
CSRDIR="/var/opt/certinel/requests"
KEYDIR="/var/opt/certinel/private"
ISSUED_DIR="/var/opt/certinel/issued"

# ----- Subject DN applied to every generated CSR -----
# Rendered in this order (C, ST, L, O, OUs...), then CN last. These are
# fallback defaults only; the dashboard's admin UI writes an override
# (subject.conf, sourced below) so the organizational identity is configured
# per deployment instead of hand-edited here. Leave a field empty to omit it.
SUBJECT_C="US"
SUBJECT_ST=""
SUBJECT_L=""
SUBJECT_O="Example Organization"
SUBJECT_OUS=("IT")

# ----- Domain qualification -----
# Short names (no dot) in the certlist get this suffix appended, both as the
# CN and in DNS SANs: "test" -> "test.example.com". Applies only to
# hostname-style entries, never to IPs or email addresses.
# Leave empty to disable qualification.
DOMAIN_SUFFIX="example.com"
# Advanced subject tags (admin-configured): alternate selectable domain
# suffixes, custom DN attributes (field:value), and extra SANs added to every
# cert. Default empty.
SUBJECT_DOMAIN_ALTS=()
SUBJECT_XDN=()
SUBJECT_XSANS=()

# Admin-configured subject override, written by the dashboard via the
# `write-subject` subcommand. PARSED as simple KEY=VALUE (NOT sourced - this
# content originates from the UI, so we never eval it) and wins over the
# defaults above, making the subject DN editable from the admin UI.
#   C=US / ST=.. / L=.. / O=.. / DOMAIN_SUFFIX=.. (one each); OU=.. repeatable;
#   DOMAIN_SUFFIX_ALT=.. (alt suffixes), XDN=field:value, XSAN=entry (repeatable)
SUBJECT_CONF="$(dirname "${BASH_SOURCE[0]}")/subject.conf"
if [[ -r "$SUBJECT_CONF" ]]; then
    SUBJECT_OUS=()
    SUBJECT_DOMAIN_ALTS=()
    SUBJECT_XDN=()
    SUBJECT_XSANS=()
    while IFS='=' read -r _k _v; do
        case "$_k" in
            C)                SUBJECT_C="$_v" ;;
            ST)               SUBJECT_ST="$_v" ;;
            L)                SUBJECT_L="$_v" ;;
            O)                SUBJECT_O="$_v" ;;
            OU)               [[ -n "$_v" ]] && SUBJECT_OUS+=("$_v") ;;
            DOMAIN_SUFFIX)    DOMAIN_SUFFIX="$_v" ;;
            DOMAIN_SUFFIX_ALT) [[ -n "$_v" ]] && SUBJECT_DOMAIN_ALTS+=("$_v") ;;
            XDN)              [[ -n "$_v" ]] && SUBJECT_XDN+=("$_v") ;;
            XSAN)             [[ -n "$_v" ]] && SUBJECT_XSANS+=("$_v") ;;
        esac
    done < "$SUBJECT_CONF"
    unset _k _v
fi

# Per-request domain-suffix choice: the requester may pick an alternate suffix.
# Honour it ONLY if it matches the configured primary or an admin-listed
# alternate - never trust an arbitrary value (defense in depth; runs as root).
# Passed as the generate-typed domain argument (sudo strips env, so not env).
apply_domain_choice() {
    local choice="$1" ok="" d
    [[ -z "$choice" ]] && return 0
    [[ "$choice" == "$DOMAIN_SUFFIX" ]] && ok=1
    for d in "${SUBJECT_DOMAIN_ALTS[@]}"; do
        [[ "$choice" == "$d" ]] && ok=1
    done
    if [[ -n "$ok" ]]; then DOMAIN_SUFFIX="$choice"
    else audit "domain_override deny value=$choice"; fi
}
# Env path kept for tests / non-sudo callers (sudo strips it in production).
[[ -n "${CERTINEL_DOMAIN_SUFFIX:-}" ]] && apply_domain_choice "$CERTINEL_DOMAIN_SUFFIX"

audit() { /usr/bin/logger -p authpriv.notice -t certinel-helper -- "$@"; }

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

read_subject() {
    [[ -r "$SUBJECT_CONF" ]] && cat "$SUBJECT_CONF" || true
}

write_subject() {
    # Install the admin-configured subject override (KEY=VALUE lines, parsed -
    # never sourced - by this file). Reject anything that isn't an allowed key
    # with a safe single-line value (no control chars); the dashboard already
    # sanitizes, this is defense in depth. Caps total size.
    local tmp
    tmp="$(mktemp "$(dirname "$SUBJECT_CONF")/.subject.XXXXXX")"
    tr -d '\r' | head -c 8192 > "$tmp"
    # Every non-empty line must be KEY=value where KEY is one of the allowed
    # subject keys and value has no control characters or shell-dangerous bytes.
    if grep -nvE '^$|^(C|ST|L|O|OU|DOMAIN_SUFFIX|DOMAIN_SUFFIX_ALT)=[A-Za-z0-9 ._,&/()@:-]*$|^XDN=[A-Za-z0-9.]+:[A-Za-z0-9 ._,&/()@:-]*$|^XSAN=[A-Za-z0-9 ._@:-]+$' "$tmp" | grep -q .; then
        rm -f "$tmp"
        audit "write_subject deny invalid_content"
        echo "ERROR: invalid subject content" >&2
        exit 2
    fi
    install -m 0644 -o root -g root "$tmp" "$SUBJECT_CONF"
    rm -f "$tmp"
    audit "write_subject ok bytes=$(stat -c%s "$SUBJECT_CONF")"
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
