"""ACME client is a FREE Community signing backend.

Obtaining certs FROM an external ACME CA (Let's Encrypt / step-ca / any RFC 8555
CA) uses a free, open protocol, so the ACME *client* ships free with Community
alongside OpenBao. What stays Commercial: the cloud DNS-01 solvers (acme_dns:
Cloudflare/Route53/Azure) and the ACME *server* (ca.server.acme).

These invariants hold on every edition, so this test is edition-robust: it keys
off whether the premium acme_dns module physically ships, not off the branch.
"""
import importlib
import os
import pathlib
import sys

import pytest

# NO tier marker: this verifies the FREE-tier (Community) behavior, so it must
# run on the Community build (rank 0). It is edition-robust — it branches on
# whether the premium acme_dns module ships, not on the build edition.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))


def _has_acme_dns():
    try:
        import acme_dns  # noqa: F401
        return True
    except ImportError:
        return False


def test_acme_client_is_not_a_licensed_capability():
    """The ACME client backend must NOT be in the licensed set on any edition —
    that's what makes it free (grant-all default), unlike every other backend."""
    import capabilities
    assert "ca.signing.acme" not in capabilities.LICENSED_CAPABILITIES
    assert "ca.signing.acme" not in capabilities.COMMERCIAL_CAPABILITIES


def test_acme_client_entitled_in_hardened_build_without_license(monkeypatch):
    """Free means free: entitled even in a hardened release build with no license
    and no dev override — proving it isn't leaking through the dev backdoor."""
    monkeypatch.setenv("CERTINEL_RELEASE", "1")
    monkeypatch.delenv("CSR_ENTITLEMENTS", raising=False)
    import build_mode
    import capabilities
    importlib.reload(build_mode)
    assert build_mode.is_release() and not build_mode.dev_overrides_allowed()
    assert capabilities.is_entitled("ca.signing.acme") is True
    # the ACME *server* and the paid signing backends stay premium (no license)
    assert capabilities.is_entitled("ca.server.acme") is False
    assert capabilities.is_entitled("ca.signing.windows_ca") is False


def test_free_solvers_construct():
    """HTTP-01 + internal DNS-01 (rfc2136) solvers live in acme_client, which
    ships in every build including Community."""
    import acme_client
    assert acme_client.Http01WebrootSolver("/var/www/acme") is not None
    assert acme_client.Dns01Rfc2136Solver(
        "ns1.example.com", "acme-update.", "c2VjcmV0",
        tsig_algo="hmac-sha256", port=53) is not None


def test_sign_core_gate_matches_capabilities():
    """The signing core must gate on the capability layer, not a stale hard-coded
    tuple: on a Community build ACME (free) passes the gate while OpenBao and the
    enterprise backends (premium) are refused at sign time. Regression for the
    bug where sign.py allowed manual+openbao and refused ACME after ACME was made
    the free Community backend."""
    import build_mode
    import sign
    if not build_mode.is_community_build():
        pytest.skip("only meaningful on a Community build")
    # premium on Community -> refused by the entitlement gate (before any module use)
    for paid in ("openbao", "venafi", "windows_ca"):
        with pytest.raises(sign.BackendUnavailable, match="license"):
            sign.sign_csr("dummy REQUEST", {"signer_backend": paid})
    # ACME is free -> must NOT be blocked by the license gate (it fails later for
    # lack of ACME config, but never with the "requires a license" message).
    try:
        sign.sign_csr("dummy REQUEST", {"signer_backend": "acme"})
    except sign.BackendUnavailable as e:
        assert "license" not in str(e).lower(), "ACME must be free on Community"
    except Exception:
        pass  # expected: downstream failure (no ACME directory configured)


def test_cloud_dns_gating_matches_build():
    """When the premium acme_dns module is absent (Community build), the UI must
    advertise only free challenge paths and the cloud solver must fail with a
    friendly SignError, never a raw ImportError. When it ships (Commercial), the
    cloud options are offered."""
    import sign
    opts = [f for f in sign.PROVIDERS["acme"]["fields"]
            if f["key"] == "dns_provider"][0]["options"]
    assert "rfc2136" in opts
    if _has_acme_dns():
        assert {"cloudflare", "route53", "azure"} <= set(opts)
    else:
        assert opts == ["rfc2136"]
        sett = {"acme_challenge_type": "dns-01",
                "acme_dns_provider": "cloudflare", "acme_dns_zone": "example.com"}
        sign._get_setting = lambda k: sett.get(k)
        with pytest.raises(sign.SignError, match="Commercial"):
            sign._acme_solver()
