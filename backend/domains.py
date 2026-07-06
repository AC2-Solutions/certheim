"""domains.py - registrable-domain (eTLD+1) extraction + signing-quota math.

A license may cap how many distinct registrable domains a deployment may sign
certificates for (licensing.max_domains(); 0 = unlimited). As of v4.0.0 every
paid edition — Commercial included — is uncapped by default; the cap applies only
when a license carries an explicit max_domains. This module turns a CSR's names
into registrable domains and does the pure quota arithmetic; sign.py wires it to
the license + persisted state and enforces it at the single signing chokepoint.

Dependency-free by design (regulated / air-gapped product): CSR parsing shells
out to `openssl` like the rest of sign.py, and the public-suffix logic uses a
built-in table of common multi-label suffixes rather than a PSL dependency an
offline build can't refresh. The table isn't exhaustive - it only needs to count
correctly for the suffixes customers actually use; anything else falls back to
the last two labels (example.com, agency.gov, host.lan), which is right for the
overwhelming majority of names. Extend _MULTI_SUFFIXES as needed.
"""
import re
import subprocess

# Suffixes where the registrable domain is the last THREE labels
# (e.g. example.co.uk -> example.co.uk, not co.uk).
_MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp",
    "co.za", "org.za", "gov.za",
    "com.br", "net.br", "gov.br", "org.br",
    "com.mx", "gob.mx", "com.sg", "com.hk", "com.cn", "net.cn", "gov.cn",
    "co.in", "net.in", "org.in", "gov.in", "co.kr", "or.kr",
})

_LABEL = re.compile(r"^[a-z0-9_-]+$")


def registrable_domain(host):
    """The eTLD+1 (registrable domain) for a hostname, lowercased, or "" when the
    input isn't a countable DNS name: empty, an IP literal, a single label, or a
    bare wildcard. A leading wildcard label is stripped first
    (*.a.example.com -> example.com)."""
    h = (host or "").strip().rstrip(".").lower()
    if h.startswith("*."):
        h = h[2:]
    if not h or ":" in h or h.startswith("["):       # empty / IPv6 / bracketed
        return ""
    if re.match(r"^\d+(\.\d+){3}$", h):              # IPv4 literal
        return ""
    labels = h.split(".")
    if len(labels) < 2 or any(not _LABEL.match(lbl) for lbl in labels):
        return ""
    last2 = ".".join(labels[-2:])
    if last2 in _MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last2


def csr_domains(csr_pem):
    """Set of registrable domains a CSR names (subject CN + DNS SANs). Shells out
    to openssl; returns an empty set if the CSR can't be parsed or names nothing
    DNS-like (e.g. an IP-only or client/email cert - those aren't domain-metered)."""
    try:
        proc = subprocess.run(
            ["openssl", "req", "-noout", "-text"],
            input=csr_pem if isinstance(csr_pem, str) else csr_pem.decode("utf-8", "replace"),
            capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return set()
        out = proc.stdout
    except Exception:
        return set()
    names = set()
    m = re.search(r"Subject:.*?CN\s*=\s*([^,/\n]+)", out)
    if m:
        names.add(m.group(1).strip())
    names.update(d.strip() for d in re.findall(r"DNS:([^,\s]+)", out))
    return {d for d in (registrable_domain(n) for n in names) if d}


def over_quota(new_domains, current_domains, cap):
    """Pure quota check. Given the registrable domains a CSR introduces, the
    domains already licensed, and the cap (0 = unlimited), return
    (blocked, would_be_set, offending):

      * blocked       - True if signing would exceed the cap
      * would_be_set  - the licensed-domain set after this sign (if allowed)
      * offending     - the new domains that push it over (when blocked)

    Always allowed: an uncapped license (cap 0), a re-issue/renewal whose domains
    are all already licensed, or a union that still fits within the cap."""
    new = {d for d in (new_domains or set()) if d}
    current = set(current_domains or set())
    union = current | new
    if not cap or new <= current or len(union) <= cap:
        return (False, union, set())
    return (True, union, new - current)
