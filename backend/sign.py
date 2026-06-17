"""sign.py - certificate-signing providers (the v2 in-UI CA-signing seam).

Mirrors notify.py's provider pattern: sign_csr(csr_pem, template) dispatches to
the backend named by template['signer_backend']:

  manual  - the existing human/upload loop. sign_csr raises BackendUnavailable
            so the caller falls back to the manual cert-upload path.
  openbao - OpenBao PKI: AppRole login -> POST <mount>/sign/<role>, returns the
            signed certificate + CA chain.

Security model (see docs/v2-ca-signing-design.md):
  - The CA key NEVER touches the app box. The app holds only a narrowly-scoped
    AppRole credential (capability: update on <mount>/sign/<role> ONLY) - it can
    request a signature but can't mint a CA or read a key.
  - The AppRole role_id/secret_id come from the ENVIRONMENT (operator-managed,
    like other secrets), never from jobs.db.
  - Connection config (addr/mount/role) is non-secret and may live in
    app_settings; env vars override.
  - The OpenBao role is the authoritative policy (allowed domains/SAN/EKU/TTL);
    the app pre-checks TTL only for a clean error.
"""
import os
import json
import ssl
import urllib.request
import urllib.error


class SignError(Exception):
    """Signing failed (config, transport, or CA refusal)."""


class BackendUnavailable(SignError):
    """This template has no automated backend here - use the manual upload path."""


class SignResult:
    __slots__ = ("cert_pem", "chain_pem")

    def __init__(self, cert_pem, chain_pem=""):
        self.cert_pem = cert_pem
        self.chain_pem = chain_pem


# get_setting is injected by app.py (same pattern as capabilities.configure).
_get_setting = None


def configure(get_setting=None):
    global _get_setting
    if get_setting is not None:
        _get_setting = get_setting


def _cfg(setting_key, env_var, default=""):
    """Env var wins (operator/secret), then app_settings, then default."""
    v = os.environ.get(env_var)
    if v:
        return v.strip()
    if _get_setting is not None:
        try:
            v = _get_setting(setting_key)
        except Exception:
            v = None
        if v:
            return str(v).strip()
    return default


def _ssl_context():
    """TLS context, optionally pinned to the OpenBao CA. Falls back to the
    system trust store (the app box trusts the AC2 root, which OpenBao chains
    to). Verification is NEVER disabled."""
    ca_file = _cfg("openbao_ca_file", "CSR_OPENBAO_CA_FILE", "")
    if ca_file and os.path.isfile(ca_file):
        return ssl.create_default_context(cafile=ca_file)
    return ssl.create_default_context()


def _http(url, payload=None, token=None, timeout=15, raw=False):
    """POST (payload given) or GET (payload None) a Vault/OpenBao API path.
    Returns the parsed JSON dict, or the raw text body when raw=True (some
    endpoints like `<mount>/ca/pem` return PEM, not JSON). Raises SignError on
    transport/HTTP error."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_context()) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        raise SignError(f"OpenBao HTTP {e.code} for {_redact(url)}: {detail}")
    except urllib.error.URLError as e:
        raise SignError(f"OpenBao unreachable at {_redact(url)}: {e.reason}")
    except Exception as e:  # noqa: BLE001 - surface a clean message
        raise SignError(f"OpenBao request failed: {e}")
    if raw:
        return body
    try:
        return json.loads(body) if body else {}
    except ValueError:
        raise SignError("OpenBao returned a non-JSON response")


def _redact(url):
    # never echo a token-bearing path; the path itself is safe to log
    return url


def _openbao_addr_mount():
    addr = _cfg("openbao_addr", "CSR_OPENBAO_ADDR", "https://openbao.ac2.lan").rstrip("/")
    mount = _cfg("openbao_pki_mount", "CSR_OPENBAO_PKI_MOUNT", "pki_csr").strip("/")
    return addr, mount


def _openbao_login(addr):
    """AppRole login -> short-TTL client token. Credentials from the env only."""
    role_id = os.environ.get("CSR_OPENBAO_ROLE_ID", "").strip()
    secret_id = os.environ.get("CSR_OPENBAO_SECRET_ID", "").strip()
    if not (role_id and secret_id):
        raise SignError(
            "OpenBao AppRole credential not configured "
            "(set CSR_OPENBAO_ROLE_ID and CSR_OPENBAO_SECRET_ID in the env file)")
    data = _http(f"{addr}/v1/auth/approle/login",
                 {"role_id": role_id, "secret_id": secret_id})
    token = (data.get("auth") or {}).get("client_token")
    if not token:
        raise SignError("OpenBao AppRole login returned no token")
    return token


def _sign_openbao(csr_pem, template):
    addr, mount = _openbao_addr_mount()
    role = (template or {}).get("openbao_role") or \
        _cfg("openbao_default_role", "CSR_OPENBAO_ROLE", "csr-dashboard")
    token = _openbao_login(addr)
    payload = {"csr": csr_pem, "format": "pem"}
    ttl = (template or {}).get("max_ttl")
    if ttl:
        try:
            payload["ttl"] = f"{int(ttl)}s"
        except (TypeError, ValueError):
            pass
    data = _http(f"{addr}/v1/{mount}/sign/{role}", payload, token=token)
    d = data.get("data") or {}
    cert = d.get("certificate")
    if not cert:
        raise SignError("OpenBao sign returned no certificate")
    chain = d.get("ca_chain")
    if isinstance(chain, list):
        chain_pem = "\n".join(chain)
    elif d.get("issuing_ca"):
        chain_pem = d["issuing_ca"]
    else:
        chain_pem = ""
    return SignResult(cert, chain_pem)


# --- public API -----------------------------------------------------------

BACKENDS = ("manual", "openbao")


def sign_csr(csr_pem, template):
    """Produce a signed cert for csr_pem per the template's backend.
    Returns SignResult. Raises BackendUnavailable (manual -> use upload path)
    or SignError (a real failure)."""
    backend = ((template or {}).get("signer_backend") or "manual").strip()
    if backend == "manual":
        raise BackendUnavailable("manual signing - use the cert-upload path")
    if backend == "openbao":
        if not csr_pem or "REQUEST" not in csr_pem:
            raise SignError("no CSR to sign")
        return _sign_openbao(csr_pem, template)
    raise SignError(f"unknown signer_backend: {backend}")


def revoke_cert(serial_number):
    """Revoke a previously-issued certificate by serial via OpenBao PKI.
    `serial_number` is OpenBao's colon-hex form (e.g. '39:dd:2a:...'). Returns
    the revocation epoch (or None). Raises SignError. Requires the AppRole
    policy to allow `update <mount>/revoke` (sign-only won't work)."""
    if not serial_number:
        raise SignError("no serial to revoke")
    addr, mount = _openbao_addr_mount()
    token = _openbao_login(addr)
    data = _http(f"{addr}/v1/{mount}/revoke",
                 {"serial_number": serial_number}, token=token)
    return (data.get("data") or {}).get("revocation_time")


def crl_ocsp_urls():
    """Best-effort distribution points for display (configured on the mount)."""
    addr, mount = _openbao_addr_mount()
    base = f"{addr}/v1/{mount}"
    return {"crl": f"{base}/crl", "ocsp": f"{base}/ocsp", "ca": f"{base}/ca/pem"}


def test_connection():
    """Admin 'Test connection': prove login works and the PKI mount answers,
    WITHOUT signing anything. Returns a small status dict; raises SignError."""
    addr, mount = _openbao_addr_mount()
    token = _openbao_login(addr)  # proves the AppRole credential is valid
    # read the mount CA to confirm the PKI mount exists/answers; it returns raw
    # PEM (not JSON), so fetch it raw and sanity-check it looks like a cert.
    ca = _http(f"{addr}/v1/{mount}/ca/pem", token=token, raw=True)
    if "BEGIN CERTIFICATE" not in (ca or ""):
        raise SignError(f"PKI mount '{mount}' did not return a CA certificate")
    return {"ok": True, "addr": addr, "mount": mount}
