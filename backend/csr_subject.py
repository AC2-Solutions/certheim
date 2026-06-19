"""csr_subject.py - configurable CSR subject DN (organization identity).

The subject attributes applied to every generated CSR (C / ST / L / O / OUs /
domain suffix) are NOT hardcoded: they're configured from the admin UI and
written to the helper's subject.conf (parsed, never sourced). Org profiles seed
sensible defaults during initial setup (OOBE); OUs are add/remove "tags".

This module is pure (no Flask/DB) so it's easy to test: it owns the profiles,
the value sanitization (must match the helper's whitelist), and the render to
the KEY=VALUE format the helper consumes.
"""
import re

# Allowed characters in a subject value. MUST stay within the helper's
# write_subject whitelist: [A-Za-z0-9 ._,&/()@:-]. Anything else is dropped.
_ALLOWED = re.compile(r"[^A-Za-z0-9 ._,&/()@:\-]")
_DOMAIN_ALLOWED = re.compile(r"[^A-Za-z0-9.\-]")
MAX_LEN = 128

# Org profiles seeded during initial setup. A profile sets country/org and a
# starter set of OUs; the admin then adds more OU tags (e.g. a combatant
# command) on top. DoD => O="U.S. Government" + OU=[DoD], NOT USEUCOM.
# Core OOBE profiles - always available in every edition.
CORE_PROFILES = [
    {"key": "commercial", "label": "Commercial / Enterprise",
     "country": "", "state": "", "locality": "", "org": "", "ous": [],
     "domain_suffix": ""},
    {"key": "blank", "label": "Start blank (configure manually)",
     "country": "", "state": "", "locality": "", "org": "", "ous": [],
     "domain_suffix": ""},
]

# Government / public-sector profiles - shown ONLY when the "Public Sector" pack
# is licensed (capability profiles.public_sector). See backend/licensing.py.
PUBLIC_SECTOR_PROFILES = [
    {"key": "dod", "label": "U.S. Department of Defense (DoD)",
     "country": "US", "state": "", "locality": "", "org": "U.S. Government",
     "ous": ["DoD"], "domain_suffix": ""},
    {"key": "dod_army", "label": "U.S. Army",
     "country": "US", "state": "", "locality": "", "org": "U.S. Government",
     "ous": ["DoD", "USA"], "domain_suffix": ""},
    {"key": "dod_af", "label": "U.S. Air Force",
     "country": "US", "state": "", "locality": "", "org": "U.S. Government",
     "ous": ["DoD", "USAF"], "domain_suffix": ""},
    {"key": "dod_navy", "label": "U.S. Navy",
     "country": "US", "state": "", "locality": "", "org": "U.S. Government",
     "ous": ["DoD", "USN"], "domain_suffix": ""},
    {"key": "dod_usmc", "label": "U.S. Marine Corps",
     "country": "US", "state": "", "locality": "", "org": "U.S. Government",
     "ous": ["DoD", "USMC"], "domain_suffix": ""},
    {"key": "dod_sf", "label": "U.S. Space Force",
     "country": "US", "state": "", "locality": "", "org": "U.S. Government",
     "ous": ["DoD", "USSF"], "domain_suffix": ""},
    {"key": "fed_civilian", "label": "U.S. Federal Civilian Agency",
     "country": "US", "state": "", "locality": "", "org": "U.S. Government",
     "ous": [], "domain_suffix": ""},
]

# Full list kept for internal profile-by-key lookup + back-compat.
ORG_PROFILES = CORE_PROFILES + PUBLIC_SECTOR_PROFILES

# Quick-add OU "tags". Core ones are generic; the public-sector set (services,
# combatant commands, agencies) is licensed.
CORE_SUGGESTED_OUS = ["IT", "Security", "Engineering", "Operations", "PKI"]
PUBLIC_SECTOR_OUS = [
    "DoD", "USA", "USAF", "USN", "USMC", "USSF", "USCG",
    "USEUCOM", "USAFRICOM", "USCENTCOM", "USINDOPACOM", "USNORTHCOM",
    "USSOUTHCOM", "USSPACECOM", "USSOCOM", "USSTRATCOM", "USTRANSCOM",
    "USCYBERCOM", "DISA",
]
SUGGESTED_OUS = CORE_SUGGESTED_OUS + PUBLIC_SECTOR_OUS


def org_profiles(public_sector=False):
    """Selectable org profiles; the public-sector pack only when licensed."""
    return CORE_PROFILES + (PUBLIC_SECTOR_PROFILES if public_sector else [])


def suggested_ous(public_sector=False):
    """Suggested OU tags; the public-sector set only when licensed."""
    return CORE_SUGGESTED_OUS + (PUBLIC_SECTOR_OUS if public_sector else [])


def sanitize(value, domain=False):
    """Reduce a value to the helper-safe whitelist, single line, capped."""
    if value is None:
        return ""
    v = str(value).replace("\n", " ").replace("\r", " ").strip()
    v = (_DOMAIN_ALLOWED if domain else _ALLOWED).sub("", v)
    return v[:MAX_LEN]


def clean_config(cfg):
    """Normalize an incoming subject config dict (from the UI) to safe values."""
    cfg = cfg or {}
    ous, seen = [], set()
    for ou in (cfg.get("ous") or []):
        s = sanitize(ou)
        if s and s.lower() not in seen:
            seen.add(s.lower())
            ous.append(s)
    return {
        "country": sanitize(cfg.get("country")),
        "state": sanitize(cfg.get("state")),
        "locality": sanitize(cfg.get("locality")),
        "org": sanitize(cfg.get("org")),
        "ous": ous[:16],
        "domain_suffix": sanitize(cfg.get("domain_suffix"), domain=True),
    }


def render_conf(cfg):
    """Render the cleaned config to the helper's subject.conf KEY=VALUE format."""
    c = clean_config(cfg)
    lines = [
        f"C={c['country']}",
        f"ST={c['state']}",
        f"L={c['locality']}",
        f"O={c['org']}",
    ]
    lines += [f"OU={ou}" for ou in c["ous"]]
    lines.append(f"DOMAIN_SUFFIX={c['domain_suffix']}")
    return "\n".join(lines) + "\n"


def preview_dn(cfg):
    """Human-readable RFC4514-ish subject preview for the UI (CN shown as a
    placeholder; the real CN is the per-request hostname)."""
    c = clean_config(cfg)
    rdns = []
    if c["country"]:
        rdns.append(f"C={c['country']}")
    if c["state"]:
        rdns.append(f"ST={c['state']}")
    if c["locality"]:
        rdns.append(f"L={c['locality']}")
    if c["org"]:
        rdns.append(f"O={c['org']}")
    rdns += [f"OU={ou}" for ou in c["ous"]]
    rdns.append("CN=<hostname>")
    return ", ".join(rdns)
