"""licensing.py - offline-verifiable license + entitlements.

Premium/edition features (starting with the government "Public Sector" pack) are
gated by a signed license the app verifies LOCALLY with an embedded vendor public
key - no activation server, so it works fully air-gapped. A license is:

    <base64url(payload_json)>.<base64url(signature)>

  payload    = {"customer","edition","entitlements":[...],"issued","expires"}
  signature  = RSA-SHA256 over the base64url(payload) bytes, signed by the
               vendor PRIVATE key (held only by the vendor; mint a license with
               tools/certinel-issue-license).

Source order: env CSR_LICENSE_FILE (a path on disk) wins, else the admin-uploaded
blob in app_settings ('license_blob'). No valid license -> no premium
entitlements -> the gated features simply don't appear in the UI.

Verification is done with `openssl dgst -verify` (no crypto dependency, matching
the rest of the app); the verified payload is cached per blob so we don't shell
out on every request.
"""
import base64
import json
import math
import os
import envcompat
import socket
import subprocess
import tempfile
import time

import build_mode

# The vendor's PUBLIC key. The matching PRIVATE key never ships - it lives only
# on the vendor's issuing machine and signs customer licenses. Rotating it means
# re-issuing licenses, so treat it as long-lived.
VENDOR_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApBorenlxBbgY0JcyQQKC
8Oncsh0mlldHa5pYDZxSMaOoRCrUaWehUjvMXagZxxIoJjtPybrUbdzcrpFKqrhu
M5ygrR4Z4o8ey0+2cokOUBMXDGji6M1YjaXC3UctJn26dQZBLC3mKNDaq7Kuobtz
VQojVKxsRFFSfHKPpxK853CeSmucIactvJmPEnTKmncU6GEi/8oDS2VaUcVufou4
twpnGhsa9C8Kzmcq6vbHpQEsljcePUVTiI16Xg8dUIikUdiSYpcdw2U8BFkjY8a2
o7H3SlNMK5o5b5ADUzVwjOefspENBk2HhK+DUpaOm+GmJkQb/lYpFO9LR4VzyHFI
TQIDAQAB
-----END PUBLIC KEY-----
"""

_get_setting = None
# blob -> verified payload dict, or {"__error__": reason}. Bounded.
_verify_cache = {}


def configure(get_setting=None):
    global _get_setting
    if get_setting is not None:
        _get_setting = get_setting


def _pubkey():
    # In a DEVELOPMENT build, an env override lets a test (or a deliberate
    # bring-your-own-key deployment) swap the trust anchor without editing code.
    # A hardened RELEASE build ignores it entirely: the embedded vendor key is
    # the only anchor, so a thief can't point verification at their own keypair
    # and self-issue licenses. See build_mode.py for why this is env-tightenable
    # but not env-loosenable.
    if build_mode.dev_overrides_allowed():
        override = envcompat.getenv("CSR_LICENSE_PUBKEY")
        if override:
            return override
    return VENDOR_PUBLIC_KEY


def _b64u_decode(s):
    if isinstance(s, str):
        s = s.encode()
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def b64u(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw_license():
    """The license blob from the env-pointed file, else the stored setting."""
    path = envcompat.getenv("CSR_LICENSE_FILE", "").strip()
    if path and os.path.isfile(path):
        try:
            return open(path).read().strip()
        except OSError:
            pass
    if _get_setting:
        return (_get_setting("license_blob") or "").strip()
    return ""


def _verify(blob, pubkey_pem):
    """Return the payload dict if the signature is valid, else raise ValueError."""
    try:
        payload_b64, sig_b64 = blob.split(".", 1)
    except ValueError:
        raise ValueError("malformed license (expected payload.signature)")
    sig = _b64u_decode(sig_b64)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as pf:
        pf.write(pubkey_pem); pub_file = pf.name
    with tempfile.NamedTemporaryFile("wb", suffix=".sig", delete=False) as sf:
        sf.write(sig); sig_file = sf.name
    try:
        p = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pub_file, "-signature", sig_file],
            input=payload_b64.encode(), capture_output=True)
        if p.returncode != 0:
            raise ValueError("signature does not verify against the vendor key")
    finally:
        for fn in (pub_file, sig_file):
            try:
                os.remove(fn)
            except OSError:
                pass
    try:
        return json.loads(_b64u_decode(payload_b64))
    except Exception:
        raise ValueError("license payload is not valid JSON")


def _payload_for(blob):
    """Verified payload for a blob (cached), or {'__error__': reason}."""
    cached = _verify_cache.get(blob)
    if cached is None:
        try:
            cached = _verify(blob, _pubkey())
        except Exception as e:  # noqa: BLE001
            cached = {"__error__": str(e)}
        if len(_verify_cache) > 16:
            _verify_cache.clear()
        _verify_cache[blob] = cached
    return cached


def _deployment_host():
    # CSR_LICENSE_HOST lets a containerized/renamed deployment declare the name a
    # license was bound to; otherwise the OS hostname is used.
    return (envcompat.getenv("CSR_LICENSE_HOST") or socket.gethostname() or "").strip()


def _binding_warnings(payload):
    """Soft, non-fatal binding tripwires. A license MAY carry a 'bind_host' claim
    (minted with `certinel-issue-license --bind-host`); if it doesn't match this
    deployment we WARN and surface it, but do NOT revoke entitlements - a
    legitimate host move shouldn't brick the app, and the mismatch makes a copied
    license self-evident in the logs and the admin UI."""
    warnings = []
    want = (payload.get("bind_host") or "").strip()
    if want and want.lower() != _deployment_host().lower():
        warnings.append(
            f"license is bound to host '{want}' but this deployment reports "
            f"'{_deployment_host() or 'unknown'}'")
    return warnings


def _community(reason):
    # The unlicensed baseline is the free Community edition. max_domains 0 =
    # uncapped: the domain limit is a paid-tier (Commercial) construct.
    return {"valid": False, "licensed": False, "edition": "community",
            "build_edition": build_mode.EDITION, "edition_mismatch": None,
            "reason": reason, "entitlements": [], "expired": False,
            "max_domains": 0}


def _default_max_domains(edition):
    """Per-edition default cap on distinct registrable domains the deployment may
    sign for. As of v4.0.0 every paid edition — Commercial included — is uncapped:
    Commercial is now a single flat plan with no per-domain metering. A license
    may still carry an explicit max_domains to cap a specific deployment, but the
    default for any edition is unlimited. 0 = unlimited."""
    return 0


# Edition ladder rank, mirroring build_mode._EDITION_RANK but keyed by a LICENSE
# edition string ("unlimited" is a Commercial-equivalent selling name). Used only
# to detect the "valid license for a higher tier than this BUILD can run" case.
_LICENSE_EDITION_RANK = {
    "community": 0, "commercial": 1, "unlimited": 1, "government": 2, "full": 3,
}


def build_mismatch(edition):
    """When a VALID license grants a higher edition than this build physically
    contains, return an actionable message; else "".

    Editions are separate build artifacts, not runtime flags: a Community build
    omits the premium code, so a Commercial (or higher) license installed on it
    can't turn anything on. The license is the key, the build is the ceiling. The
    fix is to redeploy with the matching edition image — which the customer pulls
    with the registry credentials that shipped in their license email — not to
    reinstall the license. This message makes that explicit instead of leaving
    the operator staring at a valid license with no new features."""
    want = _LICENSE_EDITION_RANK.get((edition or "").lower(), 0)
    have = build_mode.edition_rank()
    if want <= have:
        return ""
    ed = (edition or "").capitalize()
    return (f"This license grants the {ed} edition, but this deployment is the "
            f"{build_mode.EDITION.capitalize()} build — the {ed} features are not "
            f"present in this artifact, so installing the license alone does not "
            f"enable them. To upgrade, redeploy with the {ed} edition image using "
            f"the registry pull credentials from your license email (username = "
            f"license ID, token = pull token), then keep this same license. Your "
            f"data and configuration carry over.")


def info():
    """License status for the admin UI / gating.
    {valid, licensed, reason, customer, edition, build_edition, edition_mismatch,
    entitlements[], issued, expires, expired}. No/invalid license => Community
    edition. `edition` is what the license GRANTS; `build_edition` is what this
    artifact can actually run; `edition_mismatch` is non-empty when the former
    outranks the latter (see build_mismatch)."""
    blob = _raw_license()
    if not blob:
        return _community("Community Edition (no license installed)")
    p = _payload_for(blob)
    if "__error__" in p:
        return _community(f"invalid license: {p['__error__']}")
    now = time.time()
    exp = p.get("expires")
    expired = bool(exp and now > float(exp))
    if expired:
        return _community("license expired")
    edition = p.get("edition") or "commercial"
    md = p.get("max_domains")
    md = int(md) if md is not None else _default_max_domains(edition)
    # Surface a build/license edition mismatch as both a structured field (for a
    # dedicated UI banner) and a soft warning (so every existing warning surface
    # shows it too).
    mismatch = build_mismatch(edition)
    warnings = _binding_warnings(p)
    if mismatch:
        warnings = warnings + [mismatch]
    return {
        "valid": True, "licensed": True, "reason": "ok",
        "customer": p.get("customer"), "edition": edition,
        "build_edition": build_mode.EDITION, "edition_mismatch": mismatch or None,
        "entitlements": list(p.get("entitlements", [])),
        "issued": p.get("issued"), "expires": exp, "expired": False,
        "max_domains": md,
        "bind_host": p.get("bind_host"), "warnings": warnings,
    }


def entitlements():
    """Explicit entitlement keys from a currently-valid license (edition-derived
    grants are expanded by capabilities.edition_capabilities)."""
    return set(info().get("entitlements", []))


def max_domains():
    """Effective cap on distinct registrable (eTLD+1) domains this deployment may
    sign certificates for. 0 = unlimited. No/invalid/expired license (Community)
    => 0, since the cap is a paid-tier construct. sign.py enforces it offline."""
    return int(info().get("max_domains") or 0)


_SECONDS_PER_DAY = 86400


def expiry_notice(within_days):
    """A renewal warning if a *valid* license expires within `within_days`,
    else None. Drives the UI's renewal banner.

    Returns None for: no/invalid license, the Community baseline, a perpetual
    license (no `expires`), and one already expired (info() already flips an
    expired license to Community, so this never fires past the expiry date).
    Otherwise returns {days_left, expires, edition, customer}. days_left is the
    whole-day countdown, rounded UP so a partial final day still counts (44.9
    days left reads as "45"); a valid license therefore never reports 0 here
    (info() flips an expired one to Community first)."""
    i = info()
    if not i.get("valid"):
        return None
    exp = i.get("expires")
    if not exp:
        return None
    days_left = math.ceil((float(exp) - time.time()) / _SECONDS_PER_DAY)
    if days_left > within_days:
        return None
    return {
        "days_left": max(days_left, 0),
        "expires": float(exp),
        "edition": i.get("edition"),
        "customer": i.get("customer"),
    }


def reset_cache():
    _verify_cache.clear()
