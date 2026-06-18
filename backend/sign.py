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


# --- CyberArk provider (configurable slot) --------------------------------
# The framework + admin UI let an operator point at CyberArk and store its
# connection config; the actual sign/revoke API calls are intentionally a
# clearly-marked stub until wired+tested against a real CyberArk instance.
_CYBERARK_TODO = (
    "CyberArk is selected and its connection is saved, but the CyberArk signing "
    "API integration is not built in this release. Use OpenBao, or implement the "
    "CyberArk calls in sign.py (_sign_cyberark/_revoke_cyberark) against your "
    "CyberArk instance.")


def _sign_cyberark(csr_pem, template):
    raise SignError(_CYBERARK_TODO)


# --- provider registry (admin-selectable signing backends) ----------------
# Each provider declares connection fields rendered in the admin UI. A field's
# value is stored non-secret in app_settings under its `setting` key; secrets
# come from the environment (see secret_hint). 'manual' has no automated signing.
PROVIDERS = {
    "manual": {
        "label": "Manual (signers upload certs by hand)",
        "automated": False, "stub": False, "secret_hint": "", "fields": [],
    },
    "openbao": {
        "label": "OpenBao PKI",
        "automated": True, "stub": False,
        "secret_hint": "AppRole CSR_OPENBAO_ROLE_ID / CSR_OPENBAO_SECRET_ID (service env)",
        "fields": [
            {"key": "addr", "setting": "openbao_addr", "label": "OpenBao address",
             "placeholder": "https://openbao.example.com"},
            {"key": "pki_mount", "setting": "openbao_pki_mount", "label": "PKI mount",
             "placeholder": "pki_csr"},
            {"key": "default_role", "setting": "openbao_default_role", "label": "Default role",
             "placeholder": "csr-dashboard"},
        ],
    },
    "cyberark": {
        "label": "CyberArk",
        "automated": True, "stub": True,
        "secret_hint": "API token CSR_CYBERARK_TOKEN (service env)",
        "fields": [
            {"key": "base_url", "setting": "signing_cyberark_base_url",
             "label": "CyberArk base URL", "placeholder": "https://cyberark.example.com"},
            {"key": "ca_id", "setting": "signing_cyberark_ca_id",
             "label": "Issuing CA / policy ID", "placeholder": "policy or CA identifier"},
            {"key": "app_id", "setting": "signing_cyberark_app_id",
             "label": "Application ID", "placeholder": "csr-dashboard"},
        ],
    },
}

BACKENDS = tuple(PROVIDERS.keys())


def field_setting(provider, field_key):
    """Map a provider's field key -> its app_settings key (None if unknown)."""
    for f in PROVIDERS.get(provider, {}).get("fields", []):
        if f["key"] == field_key:
            return f["setting"]
    return None


def provider_meta():
    """Provider registry + current field values for the admin UI. Values pulled
    via the injected get_setting; never includes secrets."""
    out = []
    for key, p in PROVIDERS.items():
        fields = [{
            "key": f["key"], "label": f["label"],
            "placeholder": f.get("placeholder", ""),
            "value": (_get_setting(f["setting"]) if _get_setting else "") or "",
        } for f in p["fields"]]
        out.append({
            "key": key, "label": p["label"], "automated": p["automated"],
            "stub": p["stub"], "secret_hint": p["secret_hint"],
            "credential_present": _credential_present(key), "fields": fields,
        })
    return out


def _credential_present(provider):
    if provider == "openbao":
        return bool(os.environ.get("CSR_OPENBAO_ROLE_ID")
                    and os.environ.get("CSR_OPENBAO_SECRET_ID"))
    if provider == "cyberark":
        return bool(os.environ.get("CSR_CYBERARK_TOKEN"))
    return True   # manual needs no credential


def sign_csr(csr_pem, template):
    """Produce a signed cert for csr_pem per the template's backend.
    Returns SignResult. Raises BackendUnavailable (manual -> use upload path)
    or SignError (a real failure)."""
    backend = ((template or {}).get("signer_backend") or "manual").strip()
    if backend == "manual":
        raise BackendUnavailable("manual signing - use the cert-upload path")
    if not csr_pem or "REQUEST" not in csr_pem:
        raise SignError("no CSR to sign")
    if backend == "openbao":
        return _sign_openbao(csr_pem, template)
    if backend == "cyberark":
        return _sign_cyberark(csr_pem, template)
    raise SignError(f"unknown signer_backend: {backend}")


def revoke_cert(serial_number, backend="openbao"):
    """Revoke a previously-issued certificate by serial via its CA backend.
    `serial_number` is OpenBao's colon-hex form (e.g. '39:dd:2a:...'). Returns
    the revocation epoch (or None). Raises SignError. The OpenBao AppRole policy
    must allow `update <mount>/revoke` (sign-only won't work)."""
    if not serial_number:
        raise SignError("no serial to revoke")
    if backend == "openbao":
        addr, mount = _openbao_addr_mount()
        token = _openbao_login(addr)
        data = _http(f"{addr}/v1/{mount}/revoke",
                     {"serial_number": serial_number}, token=token)
        return (data.get("data") or {}).get("revocation_time")
    if backend == "cyberark":
        raise SignError(_CYBERARK_TODO)
    raise SignError(f"revoke not supported for backend: {backend}")


def crl_ocsp_urls():
    """Best-effort OpenBao distribution points for display (mount config)."""
    addr, mount = _openbao_addr_mount()
    base = f"{addr}/v1/{mount}"
    return {"crl": f"{base}/crl", "ocsp": f"{base}/ocsp", "ca": f"{base}/ca/pem"}


def test_connection(backend="openbao"):
    """Admin 'Test connection' for a provider, WITHOUT signing. Returns a small
    status dict; raises SignError."""
    if backend == "cyberark":
        raise SignError("CyberArk connection test is not built in this release; "
                        "the configuration has been saved.")
    if backend != "openbao":
        raise SignError(f"no connection test for backend: {backend}")
    addr, mount = _openbao_addr_mount()
    token = _openbao_login(addr)  # proves the AppRole credential is valid
    # read the mount CA to confirm the PKI mount exists/answers; it returns raw
    # PEM (not JSON), so fetch it raw and sanity-check it looks like a cert.
    ca = _http(f"{addr}/v1/{mount}/ca/pem", token=token, raw=True)
    if "BEGIN CERTIFICATE" not in (ca or ""):
        raise SignError(f"PKI mount '{mount}' did not return a CA certificate")
    return {"ok": True, "addr": addr, "mount": mount}
