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
import subprocess
import tempfile
import time

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
    # An env override lets a test (or a customer running their own key) swap the
    # trust anchor without editing code; defaults to the embedded vendor key.
    return os.environ.get("CSR_LICENSE_PUBKEY") or VENDOR_PUBLIC_KEY


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
    path = os.environ.get("CSR_LICENSE_FILE", "").strip()
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


def _community(reason):
    # The unlicensed baseline is the free Community edition.
    return {"valid": False, "licensed": False, "edition": "community",
            "reason": reason, "entitlements": [], "expired": False}


def info():
    """License status for the admin UI / gating.
    {valid, licensed, reason, customer, edition, entitlements[], issued,
    expires, expired}. No/invalid license => Community edition."""
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
    return {
        "valid": True, "licensed": True, "reason": "ok",
        "customer": p.get("customer"), "edition": p.get("edition") or "commercial",
        "entitlements": list(p.get("entitlements", [])),
        "issued": p.get("issued"), "expires": exp, "expired": False,
    }


def entitlements():
    """Explicit entitlement keys from a currently-valid license (edition-derived
    grants are expanded by capabilities.edition_capabilities)."""
    return set(info().get("entitlements", []))


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
