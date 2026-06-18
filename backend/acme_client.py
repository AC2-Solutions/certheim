"""acme_client.py - a minimal, dependency-free RFC 8555 (ACME) client.

The dashboard uses this to obtain certificates *from* any ACME CA (Let's
Encrypt, an internal step-ca, ZeroSSL, Sectigo/DigiCert ACME, ...) as one more
selectable signing backend (see sign.py's 'acme' provider). It is the client
half of "fit any industry": one provider reaches every RFC 8555 CA.

Design constraints (match the rest of the app):
  * **No new dependencies.** JOSE/JWS signing is done with the `openssl`
    subprocess (RS256 over an RSA account key) + stdlib (hashlib/hmac/base64/
    urllib). This keeps the air-gapped offline bundle unchanged.
  * **Pluggable challenge solvers.** Proving control of a name is deployment-
    specific, so the order flow takes a solver object. DNS-01 (internal
    RFC2136/nsupdate) and HTTP-01 (webroot) ship here; cloud-DNS solvers are a
    later phase.
  * **The account key is the app's own** (generated + persisted by app.py and
    passed in). It is NOT a per-customer CA credential.

Public surface:
  AcmeClient(directory_url, account_key_pem, *, ca_file=None, contact_email=None,
             eab_kid=None, eab_hmac_b64=None)
    .register() -> account_url (kid)              # idempotent (onlyReturnExisting)
    .issue(csr_pem, solver) -> (cert_pem, chain_pem)
    .revoke(cert_pem, reason=0)
  Solvers: Dns01Rfc2136Solver, Http01WebrootSolver
  new_account_key_pem() -> str                    # generate an RSA account key
"""
import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


class AcmeError(Exception):
    """An ACME protocol/transport failure (carries the CA's problem detail)."""


# --------------------------------------------------------------------------
# small crypto/encoding helpers (openssl subprocess + stdlib)
# --------------------------------------------------------------------------
def b64u(data):
    """base64url without padding (JOSE)."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _openssl(args, input_bytes=None, timeout=30):
    p = subprocess.run(["openssl", *args], input=input_bytes,
                       capture_output=True, timeout=timeout)
    if p.returncode != 0:
        raise AcmeError(f"openssl {args[0]} failed: "
                        f"{p.stderr.decode('utf-8', 'replace')[:200]}")
    return p.stdout


def new_account_key_pem():
    """Generate a fresh RSA-2048 account key (PEM). The account key signs JWS
    requests; it is distinct from any certificate key."""
    return _openssl(["genrsa", "2048"]).decode()


def _rsa_jwk(account_key_pem):
    """Public RSA JWK {kty,n,e} for the account key, with members in the exact
    lexicographic order RFC 7638 thumbprints require."""
    mod = _openssl(["rsa", "-noout", "-modulus"],
                   input_bytes=account_key_pem.encode()).decode()
    m = re.search(r"Modulus=([0-9A-Fa-f]+)", mod)
    if not m:
        raise AcmeError("could not read account key modulus")
    n = bytes.fromhex(m.group(1))
    # publicExponent (almost always 65537); parse to be correct, default F4.
    e = 65537
    txt = _openssl(["rsa", "-noout", "-text"],
                   input_bytes=account_key_pem.encode()).decode()
    em = re.search(r"publicExponent:\s*(\d+)", txt)
    if em:
        e = int(em.group(1))
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    return {"e": b64u(e_bytes), "kty": "RSA", "n": b64u(n)}


def _jwk_thumbprint(jwk):
    canon = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    return b64u(hashlib.sha256(canon).digest())


def _sign_rs256(account_key_pem, signing_input):
    """RS256 = RSASSA-PKCS1-v1_5 over SHA-256; the signature is the raw bytes."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(account_key_pem)
        keyfile = f.name
    os.chmod(keyfile, 0o600)
    try:
        sig = _openssl(["dgst", "-sha256", "-sign", keyfile],
                       input_bytes=signing_input.encode()
                       if isinstance(signing_input, str) else signing_input)
    finally:
        try:
            os.remove(keyfile)
        except OSError:
            pass
    return b64u(sig)


def csr_pem_to_der_b64u(csr_pem):
    der = _openssl(["req", "-inform", "PEM", "-outform", "DER"],
                   input_bytes=csr_pem.encode())
    return b64u(der)


def cert_pem_to_der_b64u(cert_pem):
    der = _openssl(["x509", "-inform", "PEM", "-outform", "DER"],
                   input_bytes=cert_pem.encode())
    return b64u(der)


def csr_identifiers(csr_pem):
    """DNS identifiers in a CSR (SAN dNSNames, plus the CN if it looks like a
    hostname). De-duplicated, order-stable."""
    txt = _openssl(["req", "-noout", "-text"],
                   input_bytes=csr_pem.encode()).decode()
    names = []
    san = re.search(r"Subject Alternative Name:\s*\n\s*(.+)", txt)
    if san:
        for part in san.group(1).split(","):
            part = part.strip()
            if part.lower().startswith("dns:"):
                names.append(part[4:].strip())
    cn = re.search(r"Subject:.*?CN\s*=\s*([^,/\n]+)", txt)
    if cn:
        c = cn.group(1).strip()
        if "." in c and " " not in c:
            names.append(c)
    seen, out = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    if not out:
        raise AcmeError("CSR has no DNS name to request an ACME cert for")
    return out


# --------------------------------------------------------------------------
# challenge solvers
# --------------------------------------------------------------------------
class Http01WebrootSolver:
    """HTTP-01: write the key authorization to
    <webroot>/.well-known/acme-challenge/<token>. A web server (or the CA's
    standalone reach) must serve that path on http://<domain>/ port 80."""
    challenge_type = "http-01"

    def __init__(self, webroot):
        self.webroot = webroot
        self._files = []

    def setup(self, domain, token, key_authorization):
        d = os.path.join(self.webroot, ".well-known", "acme-challenge")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, token)
        with open(path, "w") as f:
            f.write(key_authorization)
        os.chmod(path, 0o644)
        self._files.append(path)

    def cleanup(self):
        for p in self._files:
            try:
                os.remove(p)
            except OSError:
                pass
        self._files = []


class Dns01Rfc2136Solver:
    """DNS-01 via RFC2136 dynamic update (`nsupdate` + a TSIG key). Sets
    _acme-challenge.<domain> TXT to base64url(sha256(keyAuthorization)). Works
    for any name in a zone the org's DNS lets us update - the universal on-prem
    answer (no per-host agent)."""
    challenge_type = "dns-01"

    def __init__(self, server, tsig_name, tsig_secret, *, tsig_algo="hmac-sha256",
                 port=53, propagation_wait=10):
        self.server = server
        self.port = int(port or 53)
        self.tsig_name = tsig_name
        self.tsig_secret = tsig_secret
        self.tsig_algo = tsig_algo or "hmac-sha256"
        self.propagation_wait = int(propagation_wait)
        self._records = []

    def _txt_value(self, key_authorization):
        return b64u(hashlib.sha256(key_authorization.encode()).digest())

    def _nsupdate(self, lines):
        script = (f"server {self.server} {self.port}\n"
                  + "\n".join(lines) + "\nsend\n")
        yflag = f"{self.tsig_algo}:{self.tsig_name}:{self.tsig_secret}"
        p = subprocess.run(["nsupdate", "-y", yflag], input=script.encode(),
                           capture_output=True, timeout=30)
        if p.returncode != 0:
            raise AcmeError("nsupdate failed: "
                            + p.stderr.decode("utf-8", "replace")[:200])

    def setup(self, domain, token, key_authorization):
        rr = f"_acme-challenge.{domain}."
        val = self._txt_value(key_authorization)
        self._nsupdate([f"update add {rr} 60 IN TXT \"{val}\""])
        self._records.append((rr, val))
        if self.propagation_wait:
            time.sleep(self.propagation_wait)

    def cleanup(self):
        for rr, val in self._records:
            try:
                self._nsupdate([f"update delete {rr} TXT \"{val}\""])
            except AcmeError:
                pass
        self._records = []


# --------------------------------------------------------------------------
# the ACME client
# --------------------------------------------------------------------------
class AcmeClient:
    def __init__(self, directory_url, account_key_pem, *, ca_file=None,
                 contact_email=None, eab_kid=None, eab_hmac_b64=None,
                 timeout=30):
        self.directory_url = directory_url.strip()
        self.account_key_pem = account_key_pem
        self.contact_email = (contact_email or "").strip()
        self.eab_kid = (eab_kid or "").strip()
        self.eab_hmac_b64 = (eab_hmac_b64 or "").strip()
        self.timeout = timeout
        self._ctx = (ssl.create_default_context(cafile=ca_file)
                     if ca_file and os.path.isfile(ca_file)
                     else ssl.create_default_context())
        self._dir = None
        self._nonce = None
        self._kid = None
        self._jwk = _rsa_jwk(account_key_pem)

    # ---- transport -------------------------------------------------------
    def _raw(self, url, method="GET", body=None, ctype=None):
        headers = {}
        if ctype:
            headers["Content-Type"] = ctype
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ctx) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {}), e.read()
        except urllib.error.URLError as e:
            raise AcmeError(f"ACME CA unreachable at {url}: {e.reason}")

    def _directory(self):
        if self._dir is None:
            st, _, body = self._raw(self.directory_url)
            if st != 200:
                raise AcmeError(f"ACME directory HTTP {st} at {self.directory_url}")
            self._dir = json.loads(body)
        return self._dir

    def _get_nonce(self):
        if self._nonce:
            n, self._nonce = self._nonce, None
            return n
        st, hdrs, _ = self._raw(self._directory()["newNonce"], method="HEAD")
        n = hdrs.get("Replay-Nonce")
        if not n:
            raise AcmeError("CA did not return a Replay-Nonce")
        return n

    def _signed_post(self, url, payload, *, use_jwk=False, _retry=True):
        """POST a JWS to `url`. payload=None sends an empty body (POST-as-GET).
        Uses the account 'kid' once registered, else the embedded JWK."""
        protected = {"alg": "RS256", "nonce": self._get_nonce(), "url": url}
        if use_jwk:
            protected["jwk"] = self._jwk
        else:
            protected["kid"] = self._kid
        p64 = b64u(json.dumps(protected, separators=(",", ":")))
        y64 = "" if payload is None else b64u(json.dumps(payload, separators=(",", ":")))
        sig = _sign_rs256(self.account_key_pem, f"{p64}.{y64}")
        jws = json.dumps({"protected": p64, "payload": y64, "signature": sig}).encode()
        st, hdrs, body = self._raw(url, method="POST", body=jws,
                                   ctype="application/jose+json")
        self._nonce = hdrs.get("Replay-Nonce") or self._nonce
        if st >= 400:
            prob = {}
            try:
                prob = json.loads(body)
            except ValueError:
                pass
            if _retry and prob.get("type", "").endswith(":badNonce"):
                return self._signed_post(url, payload, use_jwk=use_jwk, _retry=False)
            raise AcmeError(f"ACME {prob.get('type','error')} ({st}) for {url}: "
                            f"{prob.get('detail', body[:200])}")
        return st, hdrs, body

    # ---- account ---------------------------------------------------------
    def _eab(self, new_account_url):
        """External Account Binding object (HS256 JWS of the account JWK keyed by
        the CA-issued HMAC) - required by many commercial ACME CAs."""
        eprot = b64u(json.dumps({"alg": "HS256", "kid": self.eab_kid,
                                 "url": new_account_url}, separators=(",", ":")))
        epay = b64u(json.dumps(self._jwk, separators=(",", ":")))
        # The EAB HMAC key is base64url (per RFC 8555 deployments); pad + decode.
        raw = self.eab_hmac_b64 + "=" * (-len(self.eab_hmac_b64) % 4)
        key = base64.urlsafe_b64decode(raw)
        sig = b64u(hmac.new(key, f"{eprot}.{epay}".encode(), hashlib.sha256).digest())
        return {"protected": eprot, "payload": epay, "signature": sig}

    def register(self):
        """Create (or look up) the ACME account; returns the account URL (kid).
        Idempotent: an existing account for this key is reused."""
        url = self._directory()["newAccount"]
        payload = {"termsOfServiceAgreed": True}
        if self.contact_email:
            payload["contact"] = [f"mailto:{self.contact_email}"]
        if self.eab_kid and self.eab_hmac_b64:
            payload["externalAccountBinding"] = self._eab(url)
        st, hdrs, _ = self._signed_post(url, payload, use_jwk=True)
        if st not in (200, 201):
            raise AcmeError(f"newAccount returned HTTP {st}")
        self._kid = hdrs.get("Location")
        if not self._kid:
            raise AcmeError("newAccount did not return an account URL")
        return self._kid

    def _ensure_account(self):
        if not self._kid:
            self.register()

    # ---- issuance --------------------------------------------------------
    def _poll(self, url, want, *, tries=20, delay=2):
        for _ in range(tries):
            _, _, body = self._signed_post(url, None)   # POST-as-GET
            obj = json.loads(body)
            status = obj.get("status")
            if status in want:
                return obj
            if status == "invalid":
                raise AcmeError(f"ACME object became invalid: {body[:300]}")
            time.sleep(delay)
        raise AcmeError(f"timed out waiting for {url} to reach {want}")

    def issue(self, csr_pem, solver):
        """Run the full ACME order for a CSR using `solver` to answer challenges.
        Returns (leaf_pem, chain_pem)."""
        self._ensure_account()
        domains = csr_identifiers(csr_pem)
        thumb = _jwk_thumbprint(self._jwk)

        order_url, order = self._new_order(domains)
        try:
            for authz_url in order["authorizations"]:
                self._do_authz(authz_url, solver, thumb)
        finally:
            solver.cleanup()

        # finalize with the CSR, then fetch the issued certificate.
        self._signed_post(order["finalize"], {"csr": csr_pem_to_der_b64u(csr_pem)})
        order = self._poll(order_url, ("valid",))
        cert_url = order.get("certificate")
        if not cert_url:
            raise AcmeError("order valid but no certificate URL")
        _, _, body = self._signed_post(cert_url, None)
        return _split_chain(body.decode("utf-8", "replace"))

    def _new_order(self, domains):
        st, hdrs, body = self._signed_post(
            self._directory()["newOrder"],
            {"identifiers": [{"type": "dns", "value": d} for d in domains]})
        if st not in (200, 201):
            raise AcmeError(f"newOrder HTTP {st}: {body[:200]}")
        return hdrs.get("Location"), json.loads(body)

    def _do_authz(self, authz_url, solver, thumb):
        _, _, body = self._signed_post(authz_url, None)
        authz = json.loads(body)
        if authz.get("status") == "valid":
            return
        domain = authz["identifier"]["value"]
        chal = next((c for c in authz["challenges"]
                     if c["type"] == solver.challenge_type), None)
        if not chal:
            raise AcmeError(f"CA offers no {solver.challenge_type} challenge "
                            f"for {domain}")
        key_auth = f"{chal['token']}.{thumb}"
        solver.setup(domain, chal["token"], key_auth)
        self._signed_post(chal["url"], {})          # tell the CA to validate
        self._poll(authz_url, ("valid",))

    # ---- revocation ------------------------------------------------------
    def revoke(self, cert_pem, reason=0):
        self._ensure_account()
        url = self._directory().get("revokeCert")
        if not url:
            raise AcmeError("CA directory has no revokeCert endpoint")
        self._signed_post(url, {"certificate": cert_pem_to_der_b64u(cert_pem),
                                "reason": int(reason)})
        return time.time()

    def test(self):
        """Reachability/registration check for the admin 'Test connection'."""
        d = self._directory()
        self._ensure_account()
        return {"ok": True, "directory": self.directory_url,
                "account": self._kid,
                "endpoints": sorted(k for k in d if isinstance(d[k], str))}


def _split_chain(pem_text):
    """Split a PEM bundle into (leaf, rest-as-chain)."""
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_text, re.DOTALL)
    if not blocks:
        raise AcmeError("ACME certificate response had no PEM certificate")
    leaf = blocks[0] + "\n"
    chain = ("\n".join(blocks[1:]) + "\n") if len(blocks) > 1 else ""
    return leaf, chain
