"""ca_providers.py - enterprise CA signing providers (Phase 3).

Real enrollment against the big enterprise / cloud PKIs, each behind the same
seam sign.py uses: a function that takes a CSR (PEM) + a config dict and returns
(cert_pem, chain_pem), raising SignError on failure.

  ejbca    - EJBCA REST `pkcs10enroll` (open-source enterprise PKI; gov/telecom/
             automotive). Optional mutual-TLS client cert.
  venafi   - Venafi TPP: certificates/request -> retrieve (poll). Bearer token.
  aws_pca  - AWS Private CA: SigV4 JSON-1.1 IssueCertificate -> GetCertificate
             (poll). Reuses the SigV4 signer from acme_dns.

Dependency-free (urllib + stdlib + openssl subprocess), matching the rest of the
app. Secrets (passwords, tokens, AWS keys, client-cert key) come from the
service environment via sign.py; non-secret config (URLs, ARNs, profile names)
from app_settings. None of these are live-tested in the homelab - request
construction is unit-tested; mark instance-validated when a customer CA exists.
"""
import base64
import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from acme_dns import aws_sigv4_headers, _sha256_hex


class CAProviderError(Exception):
    """An enrollment failure (config, transport, or CA refusal)."""


def _http(method, url, headers=None, body=None, timeout=30, context=None):
    """HTTP with an optional client-cert SSL context (EJBCA mTLS). Returns
    (status, body_bytes). Raises CAProviderError on transport failure."""
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if hasattr(e, "read") else b"")
    except urllib.error.URLError as e:
        raise CAProviderError(f"CA unreachable at {url}: {e.reason}")


def _der_b64_to_pem(b64der):
    """A base64 DER certificate (EJBCA/Venafi style) -> PEM."""
    der = base64.b64decode(b64der)
    out = subprocess.run(["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
                         input=der, capture_output=True)
    if out.returncode != 0:
        # maybe it was already PEM base64 of text; try wrapping
        raise CAProviderError("could not decode issued certificate (DER->PEM)")
    return out.stdout.decode()


def _split_pem_chain(pem_text):
    import re
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                        pem_text, re.DOTALL)
    if not blocks:
        raise CAProviderError("no PEM certificate in CA response")
    return blocks[0] + "\n", ("\n".join(blocks[1:]) + "\n" if len(blocks) > 1 else "")


# --------------------------------------------------------------------------
# EJBCA (REST pkcs10enroll)
# --------------------------------------------------------------------------
def _ejbca_context():
    """mTLS client-cert context if the env supplies one, else default TLS."""
    cert = os.environ.get("CSR_EJBCA_CLIENT_CERT", "").strip()
    key = os.environ.get("CSR_EJBCA_CLIENT_KEY", "").strip()
    ca = os.environ.get("CSR_EJBCA_CA_FILE", "").strip()
    ctx = ssl.create_default_context(cafile=ca if ca and os.path.isfile(ca) else None)
    if cert and os.path.isfile(cert):
        ctx.load_cert_chain(cert, key or None)
    return ctx


def sign_ejbca(csr_pem, cfg):
    base = (cfg.get("base_url") or "").rstrip("/")
    if not base:
        raise CAProviderError("EJBCA base URL not configured")
    payload = {
        "certificate_request": csr_pem,
        "certificate_profile_name": cfg.get("cert_profile") or "SERVER",
        "end_entity_profile_name": cfg.get("ee_profile") or "ENDUSER",
        "certificate_authority_name": cfg.get("ca_name") or "",
        "username": cfg.get("username") or "",
        "password": os.environ.get("CSR_EJBCA_PASSWORD", ""),
        "include_chain": True,
    }
    st, body = _http(
        "POST", f"{base}/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll",
        headers={"Content-Type": "application/json"},
        body=json.dumps(payload).encode(), context=_ejbca_context())
    if st >= 300:
        raise CAProviderError(f"EJBCA enroll HTTP {st}: {body.decode('utf-8','replace')[:200]}")
    data = json.loads(body or b"{}")
    cert_b64 = data.get("certificate")
    if not cert_b64:
        raise CAProviderError("EJBCA response had no certificate")
    leaf = _der_b64_to_pem(cert_b64)
    chain = ""
    for c in (data.get("certificate_chain") or []):
        try:
            chain += _der_b64_to_pem(c)
        except CAProviderError:
            pass
    return leaf, chain


def test_ejbca():
    base = (_cfg("ejbca", "base_url") or "").rstrip("/")
    if not base:
        raise CAProviderError("EJBCA base URL not configured")
    st, body = _http("GET", f"{base}/ejbca/ejbca-rest-api/v1/certificate/status",
                     context=_ejbca_context())
    # 200 (status) or 401/403 (reachable but needs auth) both prove connectivity.
    if st in (200, 401, 403):
        return {"ok": True, "addr": base, "mount": "ejbca-rest-api"}
    raise CAProviderError(f"EJBCA status check HTTP {st}")


# --------------------------------------------------------------------------
# Venafi TPP (request -> retrieve)
# --------------------------------------------------------------------------
def sign_venafi(csr_pem, cfg):
    base = (cfg.get("base_url") or "").rstrip("/")
    policy = cfg.get("policy_dn") or ""
    token = os.environ.get("CSR_VENAFI_TOKEN", "").strip()
    if not (base and policy and token):
        raise CAProviderError("Venafi needs base URL + policy DN + CSR_VENAFI_TOKEN")
    auth = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    st, body = _http("POST", f"{base}/vedsdk/certificates/request", headers=auth,
                     body=json.dumps({"PolicyDN": policy, "PKCS10": csr_pem,
                                      "Origin": "Certinel"}).encode())
    if st >= 300:
        raise CAProviderError(f"Venafi request HTTP {st}: {body.decode('utf-8','replace')[:200]}")
    cert_dn = json.loads(body or b"{}").get("CertificateDN")
    if not cert_dn:
        raise CAProviderError("Venafi request returned no CertificateDN")

    # Retrieve (the CA may need a moment to issue).
    for _ in range(15):
        st, body = _http("POST", f"{base}/vedsdk/certificates/retrieve", headers=auth,
                         body=json.dumps({"CertificateDN": cert_dn, "Format": "Base64",
                                          "IncludeChain": True, "RootFirstOrder": False}).encode())
        if st == 200:
            data = json.loads(body or b"{}")
            blob = data.get("CertificateData")
            if blob:
                pem = base64.b64decode(blob).decode("utf-8", "replace")
                if "BEGIN CERTIFICATE" in pem:
                    return _split_pem_chain(pem)
                return _der_b64_to_pem(blob), ""
        time.sleep(2)
    raise CAProviderError("Venafi certificate not ready after retrieve retries")


def test_venafi():
    base = (_cfg("venafi", "base_url") or "").rstrip("/")
    token = os.environ.get("CSR_VENAFI_TOKEN", "").strip()
    if not base:
        raise CAProviderError("Venafi base URL not configured")
    hdr = {"Authorization": f"Bearer {token}"} if token else {}
    st, _ = _http("GET", f"{base}/vedsdk/", headers=hdr)
    if st < 500:
        return {"ok": True, "addr": base, "mount": "vedsdk"}
    raise CAProviderError(f"Venafi reachability HTTP {st}")


# --------------------------------------------------------------------------
# AWS Private CA (ACM PCA) - SigV4 JSON-1.1
# --------------------------------------------------------------------------
def _pca_call(target, payload, region, access, secret, session_token=None):
    host = f"acm-pca.{region}.amazonaws.com"
    body = json.dumps(payload).encode()
    t = time.gmtime()
    headers = aws_sigv4_headers(
        "POST", host, "/", "", body, access, secret, region=region,
        service="acm-pca", amzdate=time.strftime("%Y%m%dT%H%M%SZ", t),
        datestamp=time.strftime("%Y%m%d", t), session_token=session_token,
        extra_signed={"content-type": "application/x-amz-json-1.1",
                      "x-amz-content-sha256": _sha256_hex(body),
                      "x-amz-target": f"ACMPrivateCA.{target}"})
    st, resp = _http("POST", f"https://{host}/", headers=headers, body=body)
    return st, resp


def sign_aws_pca(csr_pem, cfg):
    arn = cfg.get("ca_arn") or ""
    region = cfg.get("region") or "us-east-1"
    access = os.environ.get("CSR_AWS_PCA_ACCESS_KEY", "").strip()
    secret = os.environ.get("CSR_AWS_PCA_SECRET_KEY", "").strip()
    token = os.environ.get("CSR_AWS_PCA_SESSION_TOKEN", "").strip() or None
    if not (arn and access and secret):
        raise CAProviderError("AWS PCA needs ca_arn + CSR_AWS_PCA_ACCESS_KEY/SECRET_KEY")
    days = int(cfg.get("validity_days") or 365)
    algo = cfg.get("signing_algorithm") or "SHA256WITHRSA"

    st, resp = _pca_call("IssueCertificate", {
        "CertificateAuthorityArn": arn,
        "Csr": base64.b64encode(csr_pem.encode()).decode(),
        "SigningAlgorithm": algo,
        "Validity": {"Type": "DAYS", "Value": days},
        "IdempotencyToken": _sha256_hex(csr_pem)[:36],
    }, region, access, secret, token)
    if st >= 300:
        raise CAProviderError(f"AWS PCA IssueCertificate HTTP {st}: {resp.decode('utf-8','replace')[:200]}")
    cert_arn = json.loads(resp or b"{}").get("CertificateArn")
    if not cert_arn:
        raise CAProviderError("AWS PCA returned no CertificateArn")

    # GetCertificate - PCA issues asynchronously; poll past RequestInProgress.
    for _ in range(15):
        st, resp = _pca_call("GetCertificate",
                             {"CertificateAuthorityArn": arn, "CertificateArn": cert_arn},
                             region, access, secret, token)
        if st == 200:
            data = json.loads(resp or b"{}")
            return (data.get("Certificate", "") + "\n"), (data.get("CertificateChain", "") or "")
        if b"RequestInProgress" in resp:
            time.sleep(2); continue
        raise CAProviderError(f"AWS PCA GetCertificate HTTP {st}: {resp.decode('utf-8','replace')[:200]}")
    raise CAProviderError("AWS PCA certificate not ready after retries")


def test_aws_pca():
    arn = _cfg("aws_pca", "ca_arn") or ""
    region = _cfg("aws_pca", "region") or "us-east-1"
    access = os.environ.get("CSR_AWS_PCA_ACCESS_KEY", "").strip()
    secret = os.environ.get("CSR_AWS_PCA_SECRET_KEY", "").strip()
    token = os.environ.get("CSR_AWS_PCA_SESSION_TOKEN", "").strip() or None
    if not (arn and access and secret):
        raise CAProviderError("AWS PCA needs ca_arn + access/secret keys")
    st, resp = _pca_call("DescribeCertificateAuthority",
                         {"CertificateAuthorityArn": arn}, region, access, secret, token)
    if st == 200:
        return {"ok": True, "addr": f"acm-pca.{region}.amazonaws.com", "mount": arn.split("/")[-1]}
    raise CAProviderError(f"AWS PCA Describe HTTP {st}: {resp.decode('utf-8','replace')[:160]}")


# sign.py injects get_setting so test_* can read non-secret config.
_get_setting = None


def configure(get_setting=None):
    global _get_setting
    if get_setting is not None:
        _get_setting = get_setting


# field-key -> app_settings key mapping mirrors sign.PROVIDERS; test_* helpers
# read config via a small indirection so they don't depend on sign.py.
_SETTING_KEYS = {
    ("ejbca", "base_url"): "ejbca_base_url",
    ("venafi", "base_url"): "venafi_base_url",
    ("aws_pca", "ca_arn"): "aws_pca_ca_arn",
    ("aws_pca", "region"): "aws_pca_region",
}


def _cfg(provider, field):
    key = _SETTING_KEYS.get((provider, field))
    if key and _get_setting:
        return (_get_setting(key) or "").strip()
    return ""
