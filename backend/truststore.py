"""truststore.py - the in-app CA trust store.

Lets an admin upload root + intermediate CA certificates in the UI, builds a
single concatenated CA bundle from them, and distributes that bundle to other
hosts so a whole fleet trusts the same CAs without anyone SSHing in to hand-edit
trust anchors.

Two distribution paths (admin picks per environment):
  * push - over SSH, reusing the delivery SSH credential convention
    (secret/csr-delivery-ssh/<host> in Vault): drop the bundle and run the
    host's trust-update tool (update-ca-trust / update-ca-certificates).
  * pull - mint a scoped token; a host fetches the bundle from
    GET /api/truststore/bundle/<token> and a generated install script installs
    it. Works through a one-way firewall and in air-gapped-ish topologies where
    the app can't reach the host.

Crypto posture: like the rest of Certinel this module bundles no crypto. All
certificate parsing/validation is delegated to the system `openssl` (via
import_certs.parse_cert) and hashing to hashlib - so it inherits the host's
FIPS-validated module. The bundle is public CA material (no private keys), which
is why the pull token may be reusable within its TTL.
"""
import hashlib
import os
import secrets
import subprocess
import tempfile
import time

import import_certs

# Where update-ca-trust extracts anchors from on RHEL-family hosts; the Debian
# equivalent dir + tool are auto-detected at install time (see _INSTALL_SNIPPET).
ANCHOR_NAME = "certinel-trust-bundle.crt"

# A target hostname is interpolated into an SSH command, so it must be a plain
# host/FQDN with no shell-significant characters.
import re
_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")

_get_setting = None


def configure(get_setting=None):
    global _get_setting
    if get_setting is not None:
        _get_setting = get_setting


def _get(key, default=""):
    return ((_get_setting(key) if _get_setting else None) or default)


class TrustError(Exception):
    """A trust-store operation failed (bad input, unreachable host, ...)."""


# --------------------------------------------------------------------------- #
# Parsing / classification                                                     #
# --------------------------------------------------------------------------- #
_PEM_BLOCK_RE = import_certs.PEM_BLOCK_RE


def _full_dn(pem, which):
    """Full subject/issuer DN (RFC2253) via openssl; '' on failure."""
    flag = "-subject" if which == "subject" else "-issuer"
    p = subprocess.run(
        ["openssl", "x509", "-noout", flag, "-nameopt", "RFC2253"],
        input=pem, capture_output=True, text=True, timeout=15)
    if p.returncode != 0:
        return ""
    line = p.stdout.strip()
    pre = which + "="
    return line[len(pre):].strip() if line.startswith(pre) else line


def parse_one(pem):
    """Parse a single CA cert block. Returns a metadata dict or raises TrustError.

    role is 'root' for a self-signed CA (subject == issuer) else 'intermediate'.
    Non-CA certs are rejected - a trust store holds CAs, not leaves."""
    info = import_certs.parse_cert(pem)
    if not info or not info.get("fingerprint"):
        raise TrustError("could not parse certificate (is it valid PEM?)")
    if not info.get("is_ca"):
        raise TrustError(
            "not a CA certificate (basicConstraints CA:TRUE required) - "
            "the trust store holds roots/intermediates, not leaf certs")
    subject = _full_dn(info["pem"], "subject")
    issuer = _full_dn(info["pem"], "issuer")
    role = "root" if (subject and subject == issuer) else "intermediate"
    return {
        "pem": info["pem"],
        "fingerprint": info["fingerprint"],
        "subject": subject or (info.get("cn") or ""),
        "issuer": issuer or (info.get("issuer") or ""),
        "cn": info.get("cn"),
        "serial": info.get("serial"),
        "not_before": info.get("not_before"),
        "expires_at": info.get("expires_at"),
        "role": role,
    }


def parse_all(pem_text):
    """Parse every CA cert block in an uploaded blob. Returns [metadata...].
    Raises TrustError if no parseable CA cert is found."""
    blocks = _PEM_BLOCK_RE.findall(pem_text or "")
    if not blocks:
        raise TrustError("no PEM certificate blocks found in the upload")
    out = []
    for b in blocks:
        out.append(parse_one(b + "\n"))
    return out


# --------------------------------------------------------------------------- #
# Store CRUD                                                                    #
# --------------------------------------------------------------------------- #
def add_certs(pem_text, name=None, notes=None, actor=None):
    """Add every CA cert in pem_text to the store. Returns
    {added:[...], duplicates:[...]} by fingerprint. Skips fingerprints already
    present (idempotent re-upload)."""
    from app import db
    parsed = parse_all(pem_text)
    added, dupes = [], []
    now = time.time()
    with db() as conn:
        for p in parsed:
            exists = conn.execute(
                "SELECT id FROM trust_certs WHERE fingerprint=?",
                (p["fingerprint"],)).fetchone()
            if exists:
                dupes.append(p["fingerprint"])
                continue
            label = (name or p["cn"] or p["subject"] or "ca")[:200]
            conn.execute(
                "INSERT INTO trust_certs (name, fingerprint, pem, role, subject, "
                "issuer, serial, not_before, expires_at, enabled, created_at, "
                "created_by, notes) VALUES (?,?,?,?,?,?,?,?,?,1,?,?,?)",
                (label, p["fingerprint"], p["pem"], p["role"], p["subject"],
                 p["issuer"], p["serial"], p["not_before"], p["expires_at"],
                 now, (actor or "")[:200], (notes or None)))
            added.append(p["fingerprint"])
    return {"added": added, "duplicates": dupes}


def list_certs():
    """All stored CA certs with a computed status. Newest first."""
    from app import db
    now = time.time()
    with db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT id, name, fingerprint, role, subject, issuer, serial, "
            "not_before, expires_at, enabled, created_at, created_by, notes "
            "FROM trust_certs ORDER BY created_at DESC").fetchall()]
    for r in rows:
        exp = r.get("expires_at")
        if exp and exp < now:
            r["status"] = "expired"
        elif exp and exp < now + 30 * 86400:
            r["status"] = "expiring"
        else:
            r["status"] = "ok"
    return rows


def set_enabled(cert_id, enabled):
    from app import db
    with db() as conn:
        cur = conn.execute("UPDATE trust_certs SET enabled=? WHERE id=?",
                           (1 if enabled else 0, cert_id))
        return cur.rowcount > 0


def remove(cert_id):
    from app import db
    with db() as conn:
        cur = conn.execute("DELETE FROM trust_certs WHERE id=?", (cert_id,))
        return cur.rowcount > 0


# --------------------------------------------------------------------------- #
# Bundle assembly                                                              #
# --------------------------------------------------------------------------- #
def build_bundle(enabled_only=True):
    """Concatenate enabled CA certs into one PEM bundle (intermediates first,
    roots last - conventional chain order). Each cert is preceded by a comment
    naming it. Returns '' if the store is empty."""
    from app import db
    where = "WHERE enabled=1" if enabled_only else ""
    with db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT name, subject, role, pem FROM trust_certs " + where).fetchall()]
    # intermediates (0) before roots (1); stable by name within a group
    rows.sort(key=lambda r: (1 if r["role"] == "root" else 0,
                             (r["name"] or "").lower()))
    parts = []
    for r in rows:
        pem = r["pem"].strip()
        parts.append(f"# {r['role']}: {r['subject'] or r['name']}\n{pem}\n")
    return "".join(parts)


def bundle_meta(enabled_only=True):
    """Summary of what the current bundle would contain."""
    from app import db
    where = "WHERE enabled=1" if enabled_only else ""
    with db() as conn:
        rows = conn.execute(
            "SELECT role FROM trust_certs " + where).fetchall()
    bundle = build_bundle(enabled_only=enabled_only)
    return {
        "count": len(rows),
        "roots": sum(1 for r in rows if r["role"] == "root"),
        "intermediates": sum(1 for r in rows if r["role"] != "root"),
        "bytes": len(bundle.encode()),
        "sha256": hashlib.sha256(bundle.encode()).hexdigest() if bundle else None,
    }


# --------------------------------------------------------------------------- #
# Local install (on the Certinel host itself)                                  #
# --------------------------------------------------------------------------- #
def install_local():
    """Install the current bundle into THIS host's OS trust via the helper
    (which runs update-ca-trust as root). Returns the helper's stdout."""
    from app import run_helper
    bundle = build_bundle()
    if not bundle.strip():
        raise TrustError("trust store is empty - nothing to install")
    rc, out, err = run_helper(["install-ca-bundle"], stdin=bundle, timeout=60)
    if rc != 0:
        raise TrustError(f"local trust install failed: {(err or out or '').strip()[:200]}")
    return (out or "").strip()


# --------------------------------------------------------------------------- #
# Remote install snippet (shared by SSH push + the pull install script)        #
# --------------------------------------------------------------------------- #
def _install_body(src):
    """Bash that installs the bundle at shell-expression `src` into the host OS
    trust, auto-detecting the trust tool (RHEL update-ca-trust / Debian
    update-ca-certificates). Must run as root (callers add sudo as needed)."""
    return (
        'if command -v update-ca-trust >/dev/null 2>&1; then '
        '  install -m0644 ' + src + ' "/etc/pki/ca-trust/source/anchors/' + ANCHOR_NAME + '"; '
        '  update-ca-trust extract; '
        'elif command -v update-ca-certificates >/dev/null 2>&1; then '
        '  rm -f /usr/local/share/ca-certificates/certinel-trust-*.crt; '
        '  awk \'/BEGIN CERT/{n++} {print > ("/usr/local/share/ca-certificates/certinel-trust-" n ".crt")}\' ' + src + '; '
        '  update-ca-certificates; '
        'else echo "no supported trust tool (update-ca-trust/update-ca-certificates)" >&2; exit 1; fi; '
        'rm -f ' + src)


def _install_snippet(src_path):
    """Install snippet for a file already on the host (the pull install script)."""
    return 'set -e; SRC=' + src_path + '; ' + _install_body('"$SRC"')


# --------------------------------------------------------------------------- #
# SSH push (reuses the delivery SSH credential convention)                     #
# --------------------------------------------------------------------------- #
def push_ssh(host):
    """Push the current bundle to one host over SSH and run its trust update.
    Credential comes from Vault at secret/csr-delivery-ssh/<host>
    (username, private_key, optional port) - the same convention as cert
    delivery, so admins reuse one set of creds. Returns a short result string."""
    import deliver  # lazy: reuse Vault read + provider plumbing
    host = (host or "").strip()
    if not _HOST_RE.match(host):
        raise TrustError(f"invalid host: {host!r}")
    bundle = build_bundle()
    if not bundle.strip():
        raise TrustError("trust store is empty - nothing to push")

    try:
        cred = deliver._openbao_kv_read("csr-delivery-ssh/" + host)
    except deliver.DeliveryError as e:
        raise TrustError(str(e))
    key = cred.get("private_key")
    if not key:
        raise TrustError(f"no SSH credential at secret/csr-delivery-ssh/{host}")
    user = (cred.get("username") or "root").strip()
    port = str(cred.get("port") or "22").strip()
    sudo = "" if user == "root" else "sudo -n "

    kf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".key")
    try:
        kf.write(key if key.endswith("\n") else key + "\n")
        kf.close()
        os.chmod(kf.name, 0o600)
        # UserKnownHostsFile=/dev/null: the certinel-api unit runs ProtectHome=true,
        # so the service user's ~/.ssh is masked and ssh can't persist known_hosts
        # anyway. Pair it with accept-new so a fresh host key is taken on first use.
        ssh = ["ssh", "-i", kf.name, "-p", port,
               "-o", "StrictHostKeyChecking=accept-new",
               "-o", "UserKnownHostsFile=/dev/null",
               "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
               f"{user}@{host}"]
        # One round trip: the bundle is piped on stdin and the remote shell
        # mktemp's its own file, installs, and cleans up - all in a single shell
        # so the temp path is consistent (an earlier two-call form let $$ differ
        # between the write and the install).
        remote = ('set -e; T="$(mktemp /tmp/certinel-trust.XXXXXX)"; '
                  'umask 077; cat > "$T"; ' + _install_body('"$T"'))
        p = subprocess.run(
            ssh + [sudo + "bash -c " + _shquote(remote)],
            input=bundle, capture_output=True, text=True, timeout=90)
        if p.returncode != 0:
            raise TrustError(f"trust update on {host} failed: {(p.stderr or p.stdout)[:200]}")
        return f"installed on {user}@{host}"
    finally:
        try:
            os.remove(kf.name)
        except OSError:
            pass


def _shquote(s):
    """Single-quote a string for safe use as one bash -c argument."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def push_targets(host_filter=None):
    """Push to all enabled targets (or just host_filter). Updates each target's
    last_status/last_pushed_at. Returns [{host, ok, detail}...]."""
    from app import db
    now = time.time()
    with db() as conn:
        q = "SELECT host FROM trust_targets WHERE enabled=1"
        args = ()
        if host_filter:
            q += " AND host=?"
            args = (host_filter,)
        hosts = [r["host"] for r in conn.execute(q, args).fetchall()]
    results = []
    for h in hosts:
        try:
            detail = push_ssh(h)
            ok = True
        except Exception as e:
            detail = str(e)[:200]
            ok = False
        with db() as conn:
            conn.execute(
                "UPDATE trust_targets SET last_status=?, last_pushed_at=?, "
                "last_detail=? WHERE host=?",
                ("ok" if ok else "error", now, detail, h))
        results.append({"host": h, "ok": ok, "detail": detail})
    return results


# --- target CRUD ---
def add_target(host, label=None, actor=None):
    from app import db
    host = (host or "").strip()
    if not _HOST_RE.match(host):
        raise TrustError(f"invalid host: {host!r}")
    now = time.time()
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO trust_targets (host, label, enabled, "
            "created_at, created_by) VALUES (?,?,1,?,?)",
            (host, (label or None), now, (actor or "")[:200]))


def list_targets():
    from app import db
    with db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, host, label, enabled, last_status, last_pushed_at, "
            "last_detail, created_at FROM trust_targets ORDER BY host").fetchall()]


def remove_target(target_id):
    from app import db
    with db() as conn:
        cur = conn.execute("DELETE FROM trust_targets WHERE id=?", (target_id,))
        return cur.rowcount > 0


# --------------------------------------------------------------------------- #
# Pull: token-scoped bundle fetch + generated install script                   #
# --------------------------------------------------------------------------- #
def _public_base():
    return (_get("public_base_url", "")).rstrip("/")


def mint_pull_token(ttl=None):
    """Mint a scoped token a host can use to fetch the bundle. The bundle is
    public CA material, so the token may be reused within its TTL (max_uses 0 =
    unlimited until expiry). Returns {token, url, expires_at, ttl}."""
    from app import db
    if ttl is None:
        try:
            ttl = max(60, int(_get("trust_pull_ttl", "86400") or 86400))
        except ValueError:
            ttl = 86400
    token = secrets.token_urlsafe(32)
    now = time.time()
    with db() as conn:
        conn.execute(
            "INSERT INTO trust_pulls (token, created_at, expires_at, max_uses, uses) "
            "VALUES (?,?,?,0,0)", (token, now, now + ttl))
    base = _public_base()
    path = "/api/truststore/bundle/" + token
    return {"token": token, "url": (base + path) if base else path,
            "expires_at": now + ttl, "ttl": ttl}


def consume_pull(token, ip=None):
    """Validate a pull token and return the CURRENT bundle (computed live, so a
    host always gets the latest CAs). None if unknown/expired/exhausted - callers
    must not distinguish (no existence oracle)."""
    from app import db
    now = time.time()
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM trust_pulls WHERE token=?", (token,)).fetchone()
        if not row:
            return None
        row = dict(row)
        if now >= row["expires_at"] or (row["max_uses"] and row["uses"] >= row["max_uses"]):
            conn.execute("DELETE FROM trust_pulls WHERE token=?", (token,))
            return None
        conn.execute(
            "UPDATE trust_pulls SET uses=uses+1, last_pull_at=?, last_pull_ip=? "
            "WHERE token=?", (now, (ip or "")[:64], token))
    return build_bundle()


def purge_expired_pulls():
    from app import db
    with db() as conn:
        cur = conn.execute("DELETE FROM trust_pulls WHERE expires_at < ?",
                           (time.time(),))
        return cur.rowcount or 0


def install_script(token, base_url=None):
    """A self-contained bash installer a fleet host runs to fetch + install the
    bundle. Uses the public bundle URL for `token`; elevates with sudo if not
    run as root; auto-detects the host trust tool."""
    base = (base_url or _public_base() or "").rstrip("/")
    url = (base + "/api/truststore/bundle/" + token) if base \
        else "/api/truststore/bundle/" + token
    snippet = _install_snippet('"$TMP"')
    return (
        "#!/usr/bin/env bash\n"
        "# Certinel trust-bundle installer. Adds the Certinel CA bundle to this\n"
        "# host's OS trust store. Re-run any time to pick up CA changes.\n"
        "set -euo pipefail\n"
        f'URL="{url}"\n'
        'TMP="$(mktemp)"\n'
        'trap \'rm -f "$TMP"\' EXIT\n'
        'if command -v curl >/dev/null 2>&1; then curl -fsSL "$URL" -o "$TMP";\n'
        'elif command -v wget >/dev/null 2>&1; then wget -qO "$TMP" "$URL";\n'
        'else echo "need curl or wget" >&2; exit 1; fi\n'
        'grep -q "BEGIN CERTIFICATE" "$TMP" || { echo "no certificates fetched from $URL" >&2; exit 1; }\n'
        'SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo -n"\n'
        f'$SUDO bash -c {_shquote(snippet)}\n'
        'echo "Certinel trust bundle installed."\n')
