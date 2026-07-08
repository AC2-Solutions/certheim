#!/bin/bash
# 00-common.sh - paths, audit logging, generic file operations.
# Sourced by certinel_helper.sh; never executed directly.

# Certheim paths. The helper + its transient key scratch live off /root now
# (Phase 4b) so the systemd sandbox can mask /home + /root. Data under /var/opt,
# the helper under /opt; KEYDIR is a brief scratch (keys go to the vault).
CERTLIST_RHEL="/var/opt/certinel/certlist-rhel"
GEN_RHEL="/opt/certinel/helper/csr-rhel.sh"      # legacy generate-rhel (unused)
# Certheim data root (FHS /var/opt). Must match the app's CSR_ISSUED_DIR.
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

audit() { /usr/bin/logger -p authpriv.notice -t certinel-helper -- "$@"; }

# Admin-configured subject override, written by the dashboard via the
# `write-subject` subcommand. PARSED as simple KEY=VALUE (NOT sourced - this
# content originates from the UI, so we never eval it) and wins over the
# defaults above. The "default" named profile is mirrored to subject.conf;
# additional named profiles live in subjects/<slug>.conf and are selected
# per-request (load_subject_profile).
#   C/ST/L/O/DOMAIN_SUFFIX (one each); OU repeatable; DOMAIN_SUFFIX_ALT,
#   XDN=field:value, XSAN=entry (repeatable)
SUBJECT_CONF="$(dirname "${BASH_SOURCE[0]}")/subject.conf"
SUBJECTS_DIR="$(dirname "${BASH_SOURCE[0]}")/subjects"

load_subject_conf() {
    local path="$1" _k _v
    [[ -r "$path" ]] || return 0
    SUBJECT_OUS=(); SUBJECT_DOMAIN_ALTS=(); SUBJECT_XDN=(); SUBJECT_XSANS=()
    while IFS='=' read -r _k _v; do
        case "$_k" in
            C)                 SUBJECT_C="$_v" ;;
            ST)                SUBJECT_ST="$_v" ;;
            L)                 SUBJECT_L="$_v" ;;
            O)                 SUBJECT_O="$_v" ;;
            OU)                [[ -n "$_v" ]] && SUBJECT_OUS+=("$_v") ;;
            DOMAIN_SUFFIX)     DOMAIN_SUFFIX="$_v" ;;
            DOMAIN_SUFFIX_ALT) [[ -n "$_v" ]] && SUBJECT_DOMAIN_ALTS+=("$_v") ;;
            XDN)               [[ -n "$_v" ]] && SUBJECT_XDN+=("$_v") ;;
            XSAN)              [[ -n "$_v" ]] && SUBJECT_XSANS+=("$_v") ;;
        esac
    done < "$path"
}

# Load a NAMED subject profile, overriding the default. The slug is validated to
# a safe charset (no path traversal); a missing/invalid profile is a no-op so
# generation falls back to the default subject.
load_subject_profile() {
    local slug="$1"
    [[ -z "$slug" ]] && return 0
    if [[ ! "$slug" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; then
        audit "subject_profile deny slug=$slug"; return 0
    fi
    if [[ -r "$SUBJECTS_DIR/$slug.conf" ]]; then
        load_subject_conf "$SUBJECTS_DIR/$slug.conf"
    else
        audit "subject_profile missing slug=$slug"
    fi
}

load_subject_conf "$SUBJECT_CONF"

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

# --- container-safe ownership -------------------------------------------------
# On a VM the helper runs as root (sudo) and installs files root:root. In
# container mode it runs sudo-less as the unprivileged service user, where
# chowning to root fails ("Operation not permitted") and is pointless - the
# container is the privilege boundary. So only assert root ownership when we are
# actually root; otherwise install/keep files owned by the running user.
if [[ "$(id -u)" -eq 0 ]]; then
    inst() { install -o root -g root "$@"; }
    chown_root() { chown root:root "$@"; }
else
    inst() { install "$@"; }
    chown_root() { :; }
fi

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
    inst -m 0644 "$tmp" "$path"
    rm -f "$tmp"
    audit "write_certlist ok bytes=$(stat -c%s "$path")"
}

read_subject() {
    [[ -r "$SUBJECT_CONF" ]] && cat "$SUBJECT_CONF" || true
}

write_subject() {
    # Install an admin-configured subject override (KEY=VALUE lines, parsed -
    # never sourced - by this file). $1 = optional profile slug: with a slug,
    # writes subjects/<slug>.conf (a named profile); without, writes the default
    # subject.conf. Rejects anything that isn't an allowed key with a safe
    # single-line value (defense in depth; the dashboard already sanitizes).
    local slug="${1:-}" dest="$SUBJECT_CONF"
    if [[ -n "$slug" ]]; then
        if [[ ! "$slug" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; then
            audit "write_subject deny slug=$slug"
            echo "ERROR: invalid profile name" >&2; exit 2
        fi
        inst -d -m 0755 "$SUBJECTS_DIR"
        dest="$SUBJECTS_DIR/$slug.conf"
    fi
    local tmp
    tmp="$(mktemp "$(dirname "$dest")/.subject.XXXXXX")"
    tr -d '\r' | head -c 8192 > "$tmp"
    # Every non-empty line must be KEY=value where KEY is one of the allowed
    # subject keys and value has no control characters or shell-dangerous bytes.
    if grep -nvE '^$|^(C|ST|L|O|OU|DOMAIN_SUFFIX|DOMAIN_SUFFIX_ALT)=[A-Za-z0-9 ._,&/()@:-]*$|^XDN=[A-Za-z0-9.]+:[A-Za-z0-9 ._,&/()@:-]*$|^XSAN=[A-Za-z0-9 ._@:-]+$' "$tmp" | grep -q .; then
        rm -f "$tmp"
        audit "write_subject deny invalid_content"
        echo "ERROR: invalid subject content" >&2
        exit 2
    fi
    inst -m 0644 "$tmp" "$dest"
    rm -f "$tmp"
    audit "write_subject ok dest=$dest bytes=$(stat -c%s "$dest")"
}

delete_subject_profile() {
    local slug="$1"
    [[ "$slug" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
        audit "delete_subject_profile deny slug=$slug"
        echo "ERROR: invalid profile name" >&2; exit 2; }
    rm -f "$SUBJECTS_DIR/$slug.conf"
    audit "delete_subject_profile ok slug=$slug"
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
