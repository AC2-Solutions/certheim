"""capabilities.py - the product capability / feature-flag resolver.

A capability is AVAILABLE only when all three layers agree:

    available(cap) = entitled(cap)        # license/edition allows it
                   AND env_supports(cap)   # the deployment can physically do it
                   # (admin on/off lives in the per-feature settings, not here)

Design rules for the regulated / on-prem / air-gapped product:
  * Everything resolves OFFLINE - no phone-home, no online activation.
  * The air-gapped build is the floor: a capability that needs the internet is
    simply "unavailable in this environment", never an error.
  * Entitlements are license-agnostic for now (default: grant all); a signed,
    offline-verifiable license can populate them later with zero call-site change.

Capabilities answer "what CAN this deployment do"; the existing per-feature
settings (get_setting) still answer "what did the admin turn on".
"""
import os
import socket
import subprocess

# capability key -> required environment caps + human description.
# entitlement key defaults to the capability key.
CAPABILITIES = {
    "auth.local":   {"env": [], "desc": "Username / password authentication"},
    "auth.cac":     {"env": [], "desc": "CAC / mTLS authentication"},
    "notify.email.smtp": {"env": [], "desc": "Email via SMTP / SMG relay"},
    "notify.email.api":  {"env": ["egress_internet"],
                          "desc": "Email via Mailgun / SendGrid HTTP API"},
    "integrations.webhooks": {"env": [],
                              "desc": "Generic outbound webhooks (may be internal)"},
    "integrations.chat": {"env": ["egress_internet"],
                          "desc": "Slack / Teams / Discord notifications"},
    "integrations.slack.interactive": {"env": ["egress_internet"],
                          "desc": "Assign jobs from a Slack message"},
    "ca.signing.openbao": {"env": ["openbao"],
                          "desc": "In-UI certificate signing via OpenBao PKI"},
    "ca.signing.windows_ca": {"env": ["winca"],
                          "desc": "In-UI signing via a Windows CA (AD CS / certreq)"},
    "ca.signing.cyberark": {"env": [],
                          "desc": "In-UI signing via CyberArk (configurable slot)"},
    "ca.signing.acme": {"env": ["acme"],
                          "desc": "In-UI signing via any ACME (RFC 8555) CA"},
    "ca.signing.ejbca": {"env": ["ejbca"],
                          "desc": "In-UI signing via EJBCA (REST enrollment)"},
    "ca.signing.venafi": {"env": ["venafi"],
                          "desc": "In-UI signing via Venafi TPP"},
    "ca.signing.aws_pca": {"env": ["aws_pca"],
                          "desc": "In-UI signing via AWS Private CA (ACM PCA)"},
    "ca.server.acme": {"env": ["acme_server"],
                          "desc": "Expose an ACME (RFC 8555) server for external clients"},
    "delivery.openbao": {"env": ["openbao"],
                          "desc": "Deliver issued certs to OpenBao / Vault KV"},
    "delivery.ssh": {"env": ["openbao"],
                          "desc": "Deliver issued certs to a host over SSH (creds from Vault)"},
    "delivery.pull": {"env": [],
                          "desc": "Deliver via a scoped pull token the destination fetches"},
    "delivery.k8s": {"env": ["openbao"],
                          "desc": "Deliver issued certs into a Kubernetes TLS Secret"},
    "delivery.webhook": {"env": [],
                          "desc": "Deliver issued certs by POST to an mTLS/HMAC webhook receiver"},
    "delivery.cyberark": {"env": [],
                          "desc": "Deliver issued certs into CyberArk Conjur"},
    "trust.store": {"env": [],
                          "desc": "Build & manage a CA trust bundle from uploaded roots/intermediates"},
    "trust.distribute.ssh": {"env": ["openbao"],
                          "desc": "Push the trust bundle to fleet hosts over SSH (creds from Vault)"},
    "lifecycle.auto_renew": {"env": [],
                          "desc": "Automated certificate renewal (licensed)"},
    "profiles.public_sector": {"env": [],
                          "desc": "Government / public-sector CSR profiles + consent banners (licensed)"},
    "compliance.airgap": {"env": [], "desc": "Air-gapped / offline operation"},
}

_get_setting = None          # injected by the app (configure())
_env_cache = None            # lazily computed environment capabilities


def configure(get_setting=None):
    """Wire in the app's settings getter (used for admin-declared env flags)."""
    global _get_setting
    if get_setting is not None:
        _get_setting = get_setting


# --- environment detection -------------------------------------------------
def _setting(key, default=None):
    if _get_setting is None:
        return default
    try:
        v = _get_setting(key)
        return v if v is not None else default
    except Exception:
        return default


def _flag(name, default=False):
    """A declared env flag: env var CSR_CAP_<NAME> or setting cap_<name> wins."""
    env = os.environ.get("CSR_CAP_" + name.upper())
    if env is not None:
        return env.strip() not in ("", "0", "false", "False")
    s = _setting("cap_" + name)
    if s is not None:
        return str(s).strip() not in ("", "0", "false", "False")
    return default


def _svc_active(unit):
    try:
        r = subprocess.run(["systemctl", "is-active", "--quiet", unit], timeout=3)
        return r.returncode == 0
    except Exception:
        return False


def _probe_egress():
    """Best-effort: can we open an outbound TLS connection? Cached by caller."""
    for host in ("1.1.1.1", "api.slack.com", "8.8.8.8"):
        try:
            with socket.create_connection((host, 443), timeout=1.5):
                return True
        except OSError:
            continue
    return False


def _openssl_fips_provider():
    """The active OpenSSL FIPS provider (name + version) if loaded, else None.
    This is the real check that the *validated module* is doing the crypto -
    stronger than the kernel /proc flag alone. Certinel uses only the stdlib +
    the system `openssl`, both backed by this provider in FIPS mode."""
    try:
        out = subprocess.run(["openssl", "list", "-providers"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    # Output (indented under a flush-left "Providers:" header):
    #   Providers:
    #     fips                  <- provider name (no colon)
    #       name: Red Hat ... OpenSSL FIPS Provider
    #       version: 3.0.7-...
    #       status: active      <- attributes (key: value)
    # Indent-agnostic: a provider name line is indented with no colon; its
    # attributes are indented and have "key: value".
    block, name, ver = None, None, None
    for line in out.splitlines():
        if not line.strip() or not line[:1].isspace():
            continue                       # blank or the flush-left "Providers:"
        s = line.strip()
        if ":" not in s:
            block, name, ver = s, None, None   # a provider name (fips/default/base)
        elif block == "fips":
            if s.startswith("name:"):
                name = s.split(":", 1)[1].strip()
            elif s.startswith("version:"):
                ver = s.split(":", 1)[1].strip()
            elif s.startswith("status:") and "active" in s:
                return {"name": name or "OpenSSL FIPS Provider", "version": ver or ""}
    return None


def _openssl_major():
    """Major version of the system OpenSSL (3 on RHEL 9/10 = provider era / FIPS
    140-3; 1 on RHEL 8 = OpenSSL 1.1.1 = FIPS 140-2, no provider model). None if
    openssl is missing/unparseable."""
    try:
        out = subprocess.run(["openssl", "version"], capture_output=True,
                             text=True, timeout=5).stdout.split()
    except Exception:
        return None
    # "OpenSSL 3.0.7 1 Nov 2022" / "OpenSSL 1.1.1k  FIPS 25 Mar 2021"
    if len(out) >= 2 and out[0] == "OpenSSL":
        try:
            return int(out[1].split(".")[0])
        except ValueError:
            return None
    return None


def _detect_env():
    caps = {}
    # cheap, reliable detections
    try:
        caps["fips"] = open("/proc/sys/crypto/fips_enabled").read().strip() == "1"
    except OSError:
        caps["fips"] = False
    caps["openssl_fips_provider"] = _openssl_fips_provider()
    caps["openssl_major"] = _openssl_major()
    try:
        caps["selinux_enforcing"] = \
            open("/sys/fs/selinux/enforce").read().strip() == "1"
    except OSError:
        caps["selinux_enforcing"] = False
    caps["fapolicyd"] = _svc_active("fapolicyd")
    # declared (installer/admin) with detection fallback
    if os.environ.get("CSR_CAP_EGRESS_INTERNET") is not None \
            or _setting("cap_egress_internet") is not None:
        caps["egress_internet"] = _flag("egress_internet")
    else:
        caps["egress_internet"] = _probe_egress()
    caps["openbao"] = _flag("openbao", False)
    caps["winca"] = _flag("winca", False)
    caps["acme"] = _flag("acme", False)
    caps["ejbca"] = _flag("ejbca", False)
    caps["venafi"] = _flag("venafi", False)
    caps["aws_pca"] = _flag("aws_pca", False)
    caps["acme_server"] = _flag("acme_server", False)
    return caps


def env_caps(refresh=False):
    """Detected + declared environment capabilities (cached)."""
    global _env_cache
    if _env_cache is None or refresh:
        _env_cache = _detect_env()
    return dict(_env_cache)


def fips_status():
    """FIPS posture, validated against the platform crypto module (Certinel
    bundles no crypto - all hashing/HMAC/TLS/RNG go through the stdlib + system
    openssl). `standard` reflects the host:
      - OpenSSL 3.x (RHEL 9/10): the FIPS *provider* must be active -> 140-3.
      - OpenSSL 1.x (RHEL 8): no provider model; the kernel FIPS flag indicates
        the 1.1.1 FIPS module is in effect -> 140-2.
    `validated` = the appropriate condition for the host is met. `fips_required`
    is an admin policy; `compliant` is false only when required but not validated."""
    env = env_caps()
    kernel = bool(env.get("fips"))
    provider = env.get("openssl_fips_provider")          # {name, version} or None
    major = env.get("openssl_major")
    if provider:
        validated, standard = True, "140-3"              # OpenSSL 3.x FIPS provider active
    elif kernel and major is not None and major < 3:
        validated, standard = True, "140-2"              # OpenSSL 1.x in FIPS mode (RHEL 8)
    else:
        validated, standard = False, None                # not FIPS (or kernel on but provider missing)
    required = str(_setting("fips_required") or "").strip().lower() in ("1", "true", "yes", "on")
    return {
        "kernel_fips": kernel,
        "openssl_provider": provider,
        "openssl_major": major,
        "standard": standard,
        "validated": validated,
        "required": required,
        "compliant": validated or not required,
    }


# --- entitlements (license) ------------------------------------------------
def _entitlements():
    """Set of entitled capability keys, or None = grant all (default, license-
    agnostic). Overridable now via CSR_ENTITLEMENTS=csv; later a signed license
    file populates this with no call-site change."""
    env = os.environ.get("CSR_ENTITLEMENTS")
    if env:
        return set(x.strip() for x in env.split(",") if x.strip())
    return None


# Edition tiers. Community is the free, unlicensed baseline; Commercial,
# Unlimited, and Government are paid editions unlocked by a signed license (see
# licensing.py). Capability-wise the paid tiers stack: Unlimited and Government
# both grant the full Commercial capability set; Government adds the public-
# sector pack. The tiers differ in the signing DOMAIN CAP, not capabilities:
# Commercial meters at one registrable domain (licensing.max_domains() == 1),
# while Unlimited and Government are uncapped (0). The cap is enforced in
# sign.py, not here.
EDITIONS = ("community", "commercial", "unlimited", "government")

# Capability keys each PAID tier adds on top of free Community.
#
# The line: **Community (free) = the core request -> sign -> issue loop with the
# open-source CA.** It can generate CSRs, sign in-UI via **OpenBao** (and renew
# on demand by re-signing through it), upload manually-issued certs, and use
# fleet/audit/SMTP/local+CAC auth. No usage caps. **Commercial = breadth +
# automation:** every *other* signing backend (Windows/CyberArk/EJBCA/Venafi/
# AWS PCA, ACME client), the ACME *server*, background automated renewal, and
# connected integrations (chat / Slack-interactive / email APIs). **Government =
# Commercial + the public-sector pack.** Every key is enforced at its call site,
# so membership here is the gate. (OpenBao is deliberately NOT here -> free.)
COMMERCIAL_CAPABILITIES = {
    # in-UI signing beyond the free OpenBao + ACME-client backends. ACME
    # (ca.signing.acme) is intentionally NOT here: obtaining certs FROM an
    # external ACME CA (Let's Encrypt / step-ca / any RFC 8555 CA) uses a free,
    # open protocol, so the ACME *client* ships free with Community alongside
    # OpenBao. The core client (acme_client.py) covers HTTP-01 and internal
    # DNS-01 (rfc2136); the *cloud* DNS-01 solvers (acme_dns.py: Cloudflare/
    # Route53/Azure) and the ACME *server* (ca.server.acme) stay Commercial.
    "ca.signing.windows_ca", "ca.signing.cyberark",
    "ca.signing.ejbca", "ca.signing.venafi", "ca.signing.aws_pca",
    # the dashboard as an ACME CA
    "ca.server.acme",
    # automated delivery of issued certs to destinations
    "delivery.openbao", "delivery.ssh", "delivery.pull", "delivery.k8s",
    "delivery.webhook", "delivery.cyberark",
    # background automated renewal (on-demand renew via OpenBao stays free)
    "lifecycle.auto_renew",
    # connected integrations (basic SMTP email stays free)
    "integrations.chat", "integrations.slack.interactive", "notify.email.api",
}
# auth.cac (CAC / client-cert mTLS) ships in the Government edition and is
# available to Commercial as an explicit add-on entitlement (a Commercial
# license issued with `--entitlements auth.cac`). It is NOT in the Commercial
# base bundle, so it only appears here.
GOVERNMENT_CAPABILITIES = {"profiles.public_sector", "auth.cac"}

# Premium capabilities: never granted by the grant-all default - only by a valid
# license whose edition (or explicit entitlements) covers them. Everything else
# keeps the license-agnostic grant-all default below.
LICENSED_CAPABILITIES = COMMERCIAL_CAPABILITIES | GOVERNMENT_CAPABILITIES


def edition_capabilities(edition):
    """Licensed capability keys an edition grants (tiers stack). Unlimited is
    Commercial's capability set with no domain cap; Government adds the gov pack."""
    caps = set()
    if edition in ("commercial", "unlimited", "government"):
        caps |= COMMERCIAL_CAPABILITIES
    if edition == "government":
        caps |= GOVERNMENT_CAPABILITIES
    return caps


def _cap_build_tier(key):
    """Which build tier physically contains this capability's code.
    2 = government pack, 1 = commercial premium, 0 = always present (free)."""
    if key in GOVERNMENT_CAPABILITIES:
        return 2
    if key in COMMERCIAL_CAPABILITIES:
        return 1
    return 0


def is_entitled(key):
    if key in LICENSED_CAPABILITIES:
        # BUILD CEILING: the code for this tier must be physically present in
        # this build. The Community build has no premium code; the Commercial
        # build has no government pack; etc. No license (or dev override) can
        # grant what isn't in the artifact. The license is still required ON TOP
        # of this (checked below) — build = ceiling, license = key.
        import build_mode
        if not build_mode.build_includes_tier(_cap_build_tier(key)):
            return False
        # Explicit operator override (dev / evaluation / all-access self-host):
        # CSR_ENTITLEMENTS=* or a comma list unlocks licensed caps without a
        # license file. Honored ONLY in a development build - a hardened RELEASE
        # build ignores this backdoor, so paid capabilities require a valid
        # signed license no matter what the environment is set to.
        import build_mode
        if build_mode.dev_overrides_allowed():
            ent = _entitlements()
            if ent is not None and ("*" in ent or key in ent):
                return True
        try:
            import licensing
            info = licensing.info()
            if not info.get("valid"):
                return False
            granted = edition_capabilities(info.get("edition", "")) | set(info.get("entitlements") or [])
            return key in granted
        except Exception:
            return False
    ent = _entitlements()
    return ent is None or "*" in ent or key in ent


# --- resolution ------------------------------------------------------------
def status(key):
    spec = CAPABILITIES.get(key)
    if spec is None:
        return {"key": key, "available": False, "reason": "unknown capability", "upgrade": False}
    # `upgrade` flags a licensed capability this build/license can't use, so the
    # UI can show it grayed-out with an "upgrade to unlock" badge rather than
    # hiding it. In a Community build every licensed cap is an upgrade prompt.
    licensed = key in LICENSED_CAPABILITIES
    if not is_entitled(key):
        return {"key": key, "available": False,
                "reason": "upgrade" if licensed else "not licensed",
                "upgrade": licensed}
    env = env_caps()
    missing = [c for c in spec.get("env", []) if not env.get(c)]
    if missing:
        return {"key": key, "available": False, "upgrade": False,
                "reason": "unavailable in this environment: needs "
                          + ", ".join(missing)}
    return {"key": key, "available": True, "reason": "", "upgrade": False}


def available(key):
    return status(key)["available"]


def all_status():
    return {k: {**status(k), "desc": CAPABILITIES[k]["desc"]} for k in CAPABILITIES}
