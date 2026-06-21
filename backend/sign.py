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


# get_setting/set_setting are injected by app.py (same pattern as
# capabilities.configure). set_setting is used to persist the ACME account key.
_get_setting = None
_set_setting = None


def configure(get_setting=None, set_setting=None):
    global _get_setting, _set_setting
    if get_setting is not None:
        _get_setting = get_setting
        try:                       # let ca_providers' test_* read non-secret config
            import ca_providers
            ca_providers.configure(get_setting=get_setting)
        except Exception:
            pass
    if set_setting is not None:
        _set_setting = set_setting


def _licensed_domains():
    """The set of distinct registrable domains this deployment has already been
    licensed to sign for (persisted in app_settings, so the cap survives restarts
    and is enforced fully offline)."""
    if _get_setting is None:
        return set()
    try:
        return set(json.loads(_get_setting("licensed_domains") or "[]"))
    except Exception:
        return set()


def _set_licensed_domains(domain_set):
    if _set_setting is None:
        return
    try:
        _set_setting("licensed_domains", json.dumps(sorted(domain_set)))
    except Exception:
        pass


def _enforce_domain_quota(csr_pem):
    """Gate signing on the license's registrable-domain cap (Commercial = 1;
    Unlimited/Government uncapped). Renewals/re-issues of an already-licensed
    domain are always allowed; the first time a new domain is signed it claims a
    slot. Raises SignError when a new domain would exceed the cap. A no-op when
    the license is uncapped (max_domains 0) or the CSR names nothing DNS-like."""
    try:
        import licensing
        cap = licensing.max_domains()
    except Exception:
        cap = 0
    if not cap:
        return
    import domains as _domains
    new = _domains.csr_domains(csr_pem)
    if not new:
        return
    current = _licensed_domains()
    blocked, union, offending = _domains.over_quota(new, current, cap)
    if blocked:
        covered = ", ".join(sorted(current)) or "none yet"
        raise SignError(
            f"license domain limit reached: this license covers {cap} "
            f"registrable domain{'s' if cap != 1 else ''} ({covered}); signing "
            f"for {', '.join(sorted(offending))} would exceed it. Upgrade to the "
            f"Unlimited edition or purchase additional domains to manage more.")
    if union != current:
        _set_licensed_domains(union)


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
    system trust store (the app box trusts the internal root CA, which OpenBao chains
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
    addr = _cfg("openbao_addr", "CSR_OPENBAO_ADDR", "https://openbao.example.com").rstrip("/")
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
        _cfg("openbao_default_role", "CSR_OPENBAO_ROLE", "certinel")
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


# --- Windows CA (Active Directory Certificate Services) provider -----------
# The dashboard reaches a Windows CA over SSH (Windows OpenSSH) and drives the
# native `certreq`/`certutil` tools as a CA-admin user. Connection config (host,
# CA config string, ssh user) is admin-set; the SSH private key path + optional
# known_hosts come from the environment (secret), never the DB.
def _winca_cfg():
    return {
        "host": _cfg("winca_host", "CSR_WINCA_HOST", ""),
        "config": _cfg("winca_config", "CSR_WINCA_CONFIG", ""),
        "user": _cfg("winca_ssh_user", "CSR_WINCA_SSH_USER", "Administrator"),
        # Enterprise (domain-joined) CA: a certificate template makes certreq
        # issue against that template (auto-enroll policy). Blank = standalone CA.
        "template": _cfg("winca_template", "CSR_WINCA_TEMPLATE", ""),
        "key": os.environ.get("CSR_WINCA_SSH_KEY", "").strip(),
        "known_hosts": os.environ.get("CSR_WINCA_KNOWN_HOSTS", "").strip(),
    }


def _winca_run_ps(ps_script, timeout=60):
    """Run a PowerShell script on the Windows CA host over SSH (key auth) and
    return its stdout. The script is passed base64 (-EncodedCommand) to avoid
    all quoting issues across the bash->ssh->powershell boundary."""
    import base64
    import subprocess
    c = _winca_cfg()
    if not c["host"]:
        raise SignError("Windows CA host not configured")
    if not c["key"] or not os.path.isfile(c["key"]):
        raise SignError("Windows CA SSH key not configured (CSR_WINCA_SSH_KEY)")
    b64 = base64.b64encode(ps_script.encode("utf-16-le")).decode()
    opts = ["ssh", "-i", c["key"], "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=20"]
    if c["known_hosts"]:
        opts += ["-o", "StrictHostKeyChecking=yes",
                 "-o", "UserKnownHostsFile=" + c["known_hosts"]]
    else:
        opts += ["-o", "StrictHostKeyChecking=accept-new"]
    cmd = opts + [f'{c["user"]}@{c["host"]}',
                  "powershell -NoProfile -NonInteractive -EncodedCommand " + b64]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              env={"PATH": "/usr/bin:/bin"})
    except subprocess.TimeoutExpired:
        raise SignError("Windows CA SSH timed out")
    except Exception as e:  # noqa: BLE001
        raise SignError(f"Windows CA SSH failed: {e}")
    out = (proc.stdout or "").replace("\r", "")
    if proc.returncode != 0 and not out:
        raise SignError("Windows CA SSH error: " + (proc.stderr or "").strip()[:200])
    return out


def _extract_pem_cert(text):
    if "-----BEGIN CERTIFICATE-----" not in text:
        return None
    body = text.split("-----BEGIN CERTIFICATE-----", 1)[1]
    body = body.split("-----END CERTIFICATE-----")[0]
    return "-----BEGIN CERTIFICATE-----" + body + "-----END CERTIFICATE-----\n"


def _sign_windows_ca(csr_pem, template):
    import base64
    c = _winca_cfg()
    if not c["config"]:
        raise SignError("Windows CA config string not set (e.g. 'HOST\\CA Common Name')")
    csr_b64 = base64.b64encode(csr_pem.encode()).decode()
    # Enterprise (domain-joined) CAs issue against a certificate template; pass
    # it via -attrib. Standalone CAs leave it blank. The template name is
    # whitelisted to a safe charset so it can't break out of the quoted attrib.
    tmpl = "".join(ch for ch in (c.get("template") or "") if ch.isalnum() or ch in "-_ ")
    attrib = (" -attrib 'CertificateTemplate:" + tmpl + "'") if tmpl else ""
    # Write the CSR to a temp dir, submit to the CA, emit the issued cert, clean up.
    ps = (
        "$ErrorActionPreference='Stop'\n"
        "$d=Join-Path $env:TEMP ('csrd_'+[guid]::NewGuid().ToString('N'))\n"
        "New-Item -ItemType Directory -Force -Path $d | Out-Null\n"
        "[IO.File]::WriteAllBytes(\"$d\\r.csr\",[Convert]::FromBase64String('" + csr_b64 + "'))\n"
        "$o = certreq -submit -config '" + c["config"] + "'" + attrib + " \"$d\\r.csr\" \"$d\\c.cer\" 2>&1 | Out-String\n"
        "if(Test-Path \"$d\\c.cer\"){ Get-Content \"$d\\c.cer\" -Raw } else { 'WINCA_ERR: '+$o }\n"
        "Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue\n"
    )
    out = _winca_run_ps(ps)
    cert = _extract_pem_cert(out)
    if not cert:
        raise SignError("Windows CA did not issue a certificate: " + out.strip()[-300:])
    return SignResult(cert, "")


def _revoke_windows_ca(serial_number):
    c = _winca_cfg()
    # Windows certutil -revoke takes the serial WITHOUT colons.
    serial = (serial_number or "").replace(":", "")
    ps = ("$o = certutil -config '" + c["config"] + "' -revoke " + serial
          + " 2>&1 | Out-String; $o\n")
    out = _winca_run_ps(ps)
    if "completed successfully" in out.lower() or "revoked successfully" in out.lower():
        return None
    raise SignError("Windows CA revoke failed: " + out.strip()[-200:])


def _test_windows_ca():
    c = _winca_cfg()
    out = _winca_run_ps("(whoami); '---'; (certutil -config '" + (c["config"] or "")
                        + "' -ping 2>&1 | Out-String)", timeout=30)
    low = out.lower()
    if "interface is alive" in low or "command completed successfully" in low \
            or (c["user"].lower() in low):
        return {"ok": True, "addr": c["host"], "mount": c["config"]}
    raise SignError("Windows CA reachability check inconclusive: " + out.strip()[-200:])


# --- ACME (RFC 8555) provider ---------------------------------------------
# The dashboard acts as an ACME *client* against any RFC 8555 CA. The heavy
# lifting (JWS, orders, challenges) lives in acme_client; here we just assemble
# the client + a challenge solver from config and map errors to SignError.
def _acme_account_key():
    """The app's persistent ACME account key (PEM). Generated on first use and
    stored in app_settings so the same ACME account is reused across orders."""
    import acme_client
    key = (_get_setting("acme_account_key") if _get_setting else None) or ""
    if "PRIVATE KEY" in key:
        return key
    key = acme_client.new_account_key_pem()
    if _set_setting:
        _set_setting("acme_account_key", key)
    return key


def _acme_client():
    import acme_client
    directory = _cfg("acme_directory_url", "CSR_ACME_DIRECTORY_URL")
    if not directory:
        raise SignError("ACME directory URL is not configured")
    return acme_client.AcmeClient(
        directory, _acme_account_key(),
        ca_file=(_cfg("acme_ca_file", "CSR_ACME_CA_FILE") or None),
        contact_email=_cfg("acme_account_email", "CSR_ACME_ACCOUNT_EMAIL"),
        eab_kid=_cfg("acme_eab_kid", "CSR_ACME_EAB_KID"),
        eab_hmac_b64=os.environ.get("CSR_ACME_EAB_HMAC", "").strip(),
    )


def _acme_solver():
    """Build the configured challenge solver. HTTP-01 (webroot) or DNS-01; for
    DNS-01, dispatch on the DNS provider (rfc2136 internal, or a cloud provider
    in acme_dns). Secrets come from the service environment; non-secret config
    (zones, server) from app_settings."""
    import acme_client
    ctype = (_cfg("acme_challenge_type", "CSR_ACME_CHALLENGE_TYPE") or "dns-01").strip().lower()
    if ctype == "http-01":
        webroot = _cfg("acme_http_webroot", "CSR_ACME_HTTP_WEBROOT")
        if not webroot:
            raise SignError("HTTP-01 selected but no webroot is configured "
                            "(acme_http_webroot)")
        return acme_client.Http01WebrootSolver(webroot)

    prov = (_cfg("acme_dns_provider", "CSR_ACME_DNS_PROVIDER") or "rfc2136").strip().lower()
    zone = _cfg("acme_dns_zone", "CSR_ACME_DNS_ZONE")
    if prov in ("cloudflare", "route53", "azure"):
        import acme_dns
        if prov == "cloudflare":
            return acme_dns.Dns01CloudflareSolver(
                os.environ.get("CSR_ACME_DNS_API_TOKEN", "").strip(), zone=zone)
        if prov == "route53":
            return acme_dns.Dns01Route53Solver(
                os.environ.get("CSR_ACME_DNS_ACCESS_KEY", "").strip(),
                os.environ.get("CSR_ACME_DNS_SECRET_KEY", "").strip(), zone,
                session_token=os.environ.get("CSR_ACME_DNS_SESSION_TOKEN", "").strip() or None)
        parts = (zone or "").split("/")
        if len(parts) != 3:
            raise SignError("Azure DNS-01 needs acme_dns_zone = "
                            "'subscription/resourceGroup/zone'")
        return acme_dns.Dns01AzureSolver(
            _cfg("acme_dns_azure_tenant", "CSR_ACME_DNS_AZURE_TENANT"),
            os.environ.get("CSR_ACME_DNS_CLIENT_ID", "").strip(),
            os.environ.get("CSR_ACME_DNS_CLIENT_SECRET", "").strip(),
            parts[0], parts[1], parts[2])

    # default: internal RFC2136 / nsupdate
    server = _cfg("acme_dns_server", "CSR_ACME_DNS_SERVER")
    tsig_name = _cfg("acme_dns_tsig_name", "CSR_ACME_DNS_TSIG_NAME")
    tsig_secret = os.environ.get("CSR_ACME_DNS_TSIG_SECRET", "").strip()
    if not (server and tsig_name and tsig_secret):
        raise SignError("DNS-01 (rfc2136) requires acme_dns_server + "
                        "acme_dns_tsig_name + CSR_ACME_DNS_TSIG_SECRET (service env)")
    algo = _cfg("acme_dns_tsig_algo", "CSR_ACME_DNS_TSIG_ALGO") or "hmac-sha256"
    port = _cfg("acme_dns_port", "CSR_ACME_DNS_PORT") or "53"
    return acme_client.Dns01Rfc2136Solver(server, tsig_name, tsig_secret,
                                          tsig_algo=algo, port=int(port))


def _sign_acme(csr_pem, template):
    import acme_client
    client = _acme_client()
    solver = _acme_solver()
    try:
        leaf, chain = client.issue(csr_pem, solver)
    except acme_client.AcmeError as e:
        raise SignError(str(e))
    return SignResult(leaf, chain)


def _test_acme():
    import acme_client
    try:
        return _acme_client().test()
    except acme_client.AcmeError as e:
        raise SignError(str(e))


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
             "placeholder": "certinel"},
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
             "label": "Application ID", "placeholder": "certinel"},
        ],
    },
    "windows_ca": {
        "label": "Windows CA (AD CS / certreq)",
        "automated": True, "stub": False,
        "secret_hint": "SSH key CSR_WINCA_SSH_KEY (+ optional CSR_WINCA_KNOWN_HOSTS) in the service env",
        "fields": [
            {"key": "host", "setting": "winca_host", "label": "CA host (SSH)",
             "placeholder": "ca.example.com"},
            {"key": "config", "setting": "winca_config", "label": "CA config string",
             "placeholder": "HOSTNAME\\CA Common Name"},
            {"key": "ssh_user", "setting": "winca_ssh_user", "label": "SSH user (CA admin)",
             "placeholder": "Administrator"},
            {"key": "template", "setting": "winca_template",
             "label": "Certificate template (Enterprise CA; blank = standalone)",
             "placeholder": "WebServer"},
        ],
    },
    "acme": {
        "label": "ACME (RFC 8555 - Let's Encrypt, step-ca, ZeroSSL, ...)",
        "automated": True, "stub": False,
        "secret_hint": "EAB HMAC CSR_ACME_EAB_HMAC (commercial CAs); DNS-01 secret "
                       "in the service env per provider: TSIG CSR_ACME_DNS_TSIG_SECRET "
                       "(rfc2136), CSR_ACME_DNS_API_TOKEN (cloudflare), "
                       "CSR_ACME_DNS_ACCESS_KEY/SECRET_KEY (route53), "
                       "CSR_ACME_DNS_CLIENT_ID/CLIENT_SECRET (azure)",
        "fields": [
            {"key": "directory_url", "setting": "acme_directory_url",
             "label": "ACME directory URL",
             "placeholder": "https://acme-v02.api.letsencrypt.org/directory"},
            {"key": "account_email", "setting": "acme_account_email",
             "label": "Account contact email", "placeholder": "pki@example.com"},
            {"key": "eab_kid", "setting": "acme_eab_kid",
             "label": "EAB key id (optional)", "placeholder": "external account key id"},
            {"key": "challenge_type", "setting": "acme_challenge_type",
             "label": "Challenge type", "options": ["dns-01", "http-01"]},
            {"key": "http_webroot", "setting": "acme_http_webroot",
             "label": "HTTP-01: webroot path", "placeholder": "/var/www/acme",
             "show_if": [{"field": "challenge_type", "in": ["http-01"]}]},
            {"key": "dns_provider", "setting": "acme_dns_provider",
             "label": "DNS-01: provider",
             "options": ["rfc2136", "cloudflare", "route53", "azure"],
             "show_if": [{"field": "challenge_type", "in": ["dns-01"]}]},
            {"key": "dns_server", "setting": "acme_dns_server",
             "label": "rfc2136: update server", "placeholder": "ns1.example.com",
             "show_if": [{"field": "challenge_type", "in": ["dns-01"]},
                         {"field": "dns_provider", "in": ["rfc2136", ""]}]},
            {"key": "dns_tsig_name", "setting": "acme_dns_tsig_name",
             "label": "rfc2136: TSIG key name", "placeholder": "acme-update.",
             "show_if": [{"field": "challenge_type", "in": ["dns-01"]},
                         {"field": "dns_provider", "in": ["rfc2136", ""]}]},
            {"key": "dns_tsig_algo", "setting": "acme_dns_tsig_algo",
             "label": "rfc2136: TSIG algorithm", "placeholder": "hmac-sha256",
             "show_if": [{"field": "challenge_type", "in": ["dns-01"]},
                         {"field": "dns_provider", "in": ["rfc2136", ""]}]},
            {"key": "dns_zone", "setting": "acme_dns_zone",
             "label": "Cloud DNS zone / id",
             "placeholder": "cloudflare: example.com | route53: ZID | azure: sub/rg/zone",
             "show_if": [{"field": "challenge_type", "in": ["dns-01"]},
                         {"field": "dns_provider", "in": ["cloudflare", "route53", "azure"]}]},
            {"key": "dns_azure_tenant", "setting": "acme_dns_azure_tenant",
             "label": "azure: tenant id", "placeholder": "tenant GUID",
             "show_if": [{"field": "challenge_type", "in": ["dns-01"]},
                         {"field": "dns_provider", "in": ["azure"]}]},
        ],
    },
    "ejbca": {
        "label": "EJBCA (REST enrollment)",
        "automated": True, "stub": False,
        "secret_hint": "Enrollment password CSR_EJBCA_PASSWORD; optional mTLS "
                       "client cert CSR_EJBCA_CLIENT_CERT / CSR_EJBCA_CLIENT_KEY "
                       "(+ CSR_EJBCA_CA_FILE), all in the service env",
        "fields": [
            {"key": "base_url", "setting": "ejbca_base_url", "label": "EJBCA base URL",
             "placeholder": "https://ejbca.example.com"},
            {"key": "ca_name", "setting": "ejbca_ca_name", "label": "CA name",
             "placeholder": "ManagementCA"},
            {"key": "cert_profile", "setting": "ejbca_cert_profile",
             "label": "Certificate profile", "placeholder": "SERVER"},
            {"key": "ee_profile", "setting": "ejbca_ee_profile",
             "label": "End-entity profile", "placeholder": "ENDUSER"},
            {"key": "username", "setting": "ejbca_username", "label": "Enrollment username",
             "placeholder": "certinel"},
        ],
    },
    "venafi": {
        "label": "Venafi TPP (Trust Protection Platform)",
        "automated": True, "stub": False,
        "secret_hint": "OAuth bearer token CSR_VENAFI_TOKEN (service env)",
        "fields": [
            {"key": "base_url", "setting": "venafi_base_url", "label": "TPP base URL",
             "placeholder": "https://tpp.example.com"},
            {"key": "policy_dn", "setting": "venafi_policy_dn", "label": "Policy folder (DN)",
             "placeholder": "\\VED\\Policy\\Certificates\\Certinel"},
        ],
    },
    "aws_pca": {
        "label": "AWS Private CA (ACM PCA)",
        "automated": True, "stub": False,
        "secret_hint": "CSR_AWS_PCA_ACCESS_KEY / CSR_AWS_PCA_SECRET_KEY "
                       "(+ optional CSR_AWS_PCA_SESSION_TOKEN) in the service env",
        "fields": [
            {"key": "ca_arn", "setting": "aws_pca_ca_arn", "label": "CA ARN",
             "placeholder": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/..."},
            {"key": "region", "setting": "aws_pca_region", "label": "Region",
             "placeholder": "us-east-1"},
            {"key": "signing_algorithm", "setting": "aws_pca_signing_algorithm",
             "label": "Signing algorithm", "placeholder": "SHA256WITHRSA"},
            {"key": "validity_days", "setting": "aws_pca_validity_days",
             "label": "Validity (days)", "placeholder": "365"},
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
            # optional UI hints: a fixed option list -> <select>; show_if -> a
            # list of {field, in:[...]} conditions (all must match to display).
            "options": f.get("options"),
            "show_if": f.get("show_if"),
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
    if provider == "windows_ca":
        key = os.environ.get("CSR_WINCA_SSH_KEY", "").strip()
        return bool(key and os.path.isfile(key))
    if provider == "acme":
        # ACME needs no single mandatory env secret (public CA + HTTP-01 works
        # with none); it's "configured" once a directory URL is set. Per-config
        # requirements (EAB / TSIG) surface at test/sign time.
        return bool(_cfg("acme_directory_url", "CSR_ACME_DIRECTORY_URL"))
    if provider == "ejbca":
        return bool(os.environ.get("CSR_EJBCA_PASSWORD")
                    or os.environ.get("CSR_EJBCA_CLIENT_CERT"))
    if provider == "venafi":
        return bool(os.environ.get("CSR_VENAFI_TOKEN"))
    if provider == "aws_pca":
        return bool(os.environ.get("CSR_AWS_PCA_ACCESS_KEY")
                    and os.environ.get("CSR_AWS_PCA_SECRET_KEY"))
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
    _enforce_domain_quota(csr_pem)
    if backend == "openbao":
        return _sign_openbao(csr_pem, template)
    if backend == "cyberark":
        return _sign_cyberark(csr_pem, template)
    if backend == "windows_ca":
        return _sign_windows_ca(csr_pem, template)
    if backend == "acme":
        return _sign_acme(csr_pem, template)
    if backend in ("ejbca", "venafi", "aws_pca"):
        import ca_providers
        try:
            leaf, chain = getattr(ca_providers, "sign_" + backend)(
                csr_pem, _provider_settings(backend))
        except ca_providers.CAProviderError as e:
            raise SignError(str(e))
        return SignResult(leaf, chain)
    raise SignError(f"unknown signer_backend: {backend}")


def _provider_settings(backend):
    """Resolve a provider's non-secret connection fields from app_settings into
    a plain dict keyed by field key (what ca_providers.sign_* expect)."""
    return {f["key"]: ((_get_setting(f["setting"]) if _get_setting else "") or "")
            for f in PROVIDERS.get(backend, {}).get("fields", [])}


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
    if backend == "windows_ca":
        return _revoke_windows_ca(serial_number)
    if backend == "cyberark":
        raise SignError(_CYBERARK_TODO)
    if backend == "acme":
        # ACME revokes by certificate (not serial); the in-UI revoke path passes
        # only the serial today. Threading the stored cert PEM through is a small
        # follow-on; until then revoke at the ACME CA.
        raise SignError("ACME revocation is not wired in this build; revoke the "
                        "certificate at the ACME CA.")
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
    if backend == "windows_ca":
        return _test_windows_ca()
    if backend == "acme":
        return _test_acme()
    if backend in ("ejbca", "venafi", "aws_pca"):
        import ca_providers
        try:
            return getattr(ca_providers, "test_" + backend)()
        except ca_providers.CAProviderError as e:
            raise SignError(str(e))
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
