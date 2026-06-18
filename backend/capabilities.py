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


def _detect_env():
    caps = {}
    # cheap, reliable detections
    try:
        caps["fips"] = open("/proc/sys/crypto/fips_enabled").read().strip() == "1"
    except OSError:
        caps["fips"] = False
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
    return caps


def env_caps(refresh=False):
    """Detected + declared environment capabilities (cached)."""
    global _env_cache
    if _env_cache is None or refresh:
        _env_cache = _detect_env()
    return dict(_env_cache)


# --- entitlements (license) ------------------------------------------------
def _entitlements():
    """Set of entitled capability keys, or None = grant all (default, license-
    agnostic). Overridable now via CSR_ENTITLEMENTS=csv; later a signed license
    file populates this with no call-site change."""
    env = os.environ.get("CSR_ENTITLEMENTS")
    if env:
        return set(x.strip() for x in env.split(",") if x.strip())
    return None


def is_entitled(key):
    ent = _entitlements()
    return ent is None or "*" in ent or key in ent


# --- resolution ------------------------------------------------------------
def status(key):
    spec = CAPABILITIES.get(key)
    if spec is None:
        return {"key": key, "available": False, "reason": "unknown capability"}
    if not is_entitled(key):
        return {"key": key, "available": False, "reason": "not licensed"}
    env = env_caps()
    missing = [c for c in spec.get("env", []) if not env.get(c)]
    if missing:
        return {"key": key, "available": False,
                "reason": "unavailable in this environment: needs "
                          + ", ".join(missing)}
    return {"key": key, "available": True, "reason": ""}


def available(key):
    return status(key)["available"]


def all_status():
    return {k: {**status(k), "desc": CAPABILITIES[k]["desc"]} for k in CAPABILITIES}
