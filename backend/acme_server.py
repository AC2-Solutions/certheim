"""acme_server.py - the crypto + protocol core for the dashboard's ACME server.

Phase 4: the dashboard exposes its own RFC 8555 directory so standard ACME
clients (certbot, k8s cert-manager, acme.sh) enroll *from* it. routes_acme.py
is the HTTP layer; this module is the security-sensitive core:

  * **JWS verification** of client requests. An ACME server must verify each
    request's signature against the client's account key - which can be RSA
    (RS256) or EC P-256 (ES256). We reconstruct the public key from the JWK
    using a tiny hand-rolled ASN.1 DER encoder (no crypto dependency, matching
    the rest of the app) and verify with `openssl dgst -verify`.
  * **Key authorizations + JWK thumbprints** (RFC 7638) for challenges.
  * **HTTP-01 validation**: the server fetches
    http://<domain>/.well-known/acme-challenge/<token> and checks it equals the
    key authorization - i.e. the dashboard acts as the validation authority.
  * **Single-use nonces** for replay protection.

Nothing here touches Flask; routes_acme.py passes in DB rows / request parts.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request


class AcmeServerError(Exception):
    """Maps to an ACME problem document (urn:ietf:params:acme:error:<type>)."""

    def __init__(self, message, problem_type="malformed", status=400):
        super().__init__(message)
        self.problem_type = problem_type
        self.status = status


def b64u(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    if isinstance(s, str):
        s = s.encode()
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


# --------------------------------------------------------------------------
# minimal ASN.1 DER (only what's needed to build an SPKI public key)
# --------------------------------------------------------------------------
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF); n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _der_tlv(tag, value):
    return bytes([tag]) + _der_len(len(value)) + value


def _der_uint(b):
    """ASN.1 INTEGER from big-endian unsigned bytes (add a leading 0 if the high
    bit is set, so it isn't read as negative)."""
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return _der_tlv(0x02, b)


def _rsa_spki_pem(n, e):
    """SubjectPublicKeyInfo PEM for an RSA public key from JWK n,e (raw bytes)."""
    rsa_pub = _der_tlv(0x30, _der_uint(n) + _der_uint(e))       # SEQUENCE(n,e)
    # AlgorithmIdentifier(rsaEncryption, NULL)
    algid = bytes.fromhex("300d06092a864886f70d0101010500")
    spki = _der_tlv(0x30, algid + _der_tlv(0x03, b"\x00" + rsa_pub))  # BIT STRING
    return _pem(spki)


def _ec_p256_spki_pem(x, y):
    """SubjectPublicKeyInfo PEM for an EC P-256 public key from JWK x,y. The
    AlgorithmIdentifier + curve OID prefix is fixed for prime256v1."""
    x = x.rjust(32, b"\x00"); y = y.rjust(32, b"\x00")
    point = b"\x04" + x + y                                     # uncompressed
    # AlgorithmIdentifier(id-ecPublicKey, prime256v1) - the inner SEQUENCE only;
    # the outer SEQUENCE + BIT STRING are added below.
    algid = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    spki = _der_tlv(0x30, algid + _der_tlv(0x03, b"\x00" + point))
    return _pem(spki)


def _pem(der):
    b = base64.encodebytes(der).decode().strip()
    return f"-----BEGIN PUBLIC KEY-----\n{b}\n-----END PUBLIC KEY-----\n"


def jwk_to_pem(jwk):
    kty = jwk.get("kty")
    if kty == "RSA":
        return _rsa_spki_pem(b64u_decode(jwk["n"]), b64u_decode(jwk["e"]))
    if kty == "EC" and jwk.get("crv") == "P-256":
        return _ec_p256_spki_pem(b64u_decode(jwk["x"]), b64u_decode(jwk["y"]))
    raise AcmeServerError(f"unsupported account key type: {kty}/{jwk.get('crv')}",
                          "badPublicKey")


def jwk_thumbprint(jwk):
    """RFC 7638 thumbprint - canonical JSON with only the required members, in
    lexicographic order, per key type."""
    if jwk.get("kty") == "RSA":
        canon = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif jwk.get("kty") == "EC":
        canon = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    else:
        raise AcmeServerError("unsupported key type for thumbprint", "badPublicKey")
    return b64u(hashlib.sha256(
        json.dumps(canon, separators=(",", ":"), sort_keys=True).encode()).digest())


# --------------------------------------------------------------------------
# JWS verification
# --------------------------------------------------------------------------
def _es256_raw_to_der(sig):
    """JWS ES256 signature is R||S (32+32). openssl wants a DER ECDSA-Sig."""
    if len(sig) != 64:
        raise AcmeServerError("bad ES256 signature length", "badSignatureAlgorithm")
    r, s = sig[:32], sig[32:]
    return _der_tlv(0x30, _der_uint(r) + _der_uint(s))


def verify_jws(protected_b64, payload_b64, signature_b64, jwk, alg):
    """Verify a flattened-JWS signature over '<protected>.<payload>' against the
    client's JWK. Raises AcmeServerError on any failure. Uses openssl so we never
    hand-roll the signature math."""
    if alg not in ("RS256", "ES256"):
        raise AcmeServerError(f"unsupported alg {alg}", "badSignatureAlgorithm")
    pub_pem = jwk_to_pem(jwk)
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    sig = b64u_decode(signature_b64)
    if alg == "ES256":
        sig = _es256_raw_to_der(sig)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pub_pem); pub_file = f.name
    with tempfile.NamedTemporaryFile("wb", suffix=".sig", delete=False) as f:
        f.write(sig); sig_file = f.name
    try:
        p = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pub_file, "-signature", sig_file],
            input=signing_input, capture_output=True)
        if p.returncode != 0:
            raise AcmeServerError("JWS signature verification failed", "unauthorized", 401)
    finally:
        for fn in (pub_file, sig_file):
            try:
                os.remove(fn)
            except OSError:
                pass


def key_authorization(token, jwk):
    return f"{token}.{jwk_thumbprint(jwk)}"


# --------------------------------------------------------------------------
# challenge validation (HTTP-01)
# --------------------------------------------------------------------------
def validate_http01(domain, token, expected_key_auth, timeout=10):
    """Fetch http://<domain>/.well-known/acme-challenge/<token> and confirm it
    equals the key authorization. Returns (ok, detail)."""
    url = f"http://{domain}/.well-known/acme-challenge/{token}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192).decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code} fetching challenge"
    except Exception as e:  # noqa: BLE001
        return False, f"could not fetch challenge: {e}"
    if body == expected_key_auth:
        return True, "valid"
    return False, "key authorization mismatch"


def dns01_txt_value(key_authorization):
    """The DNS-01 TXT value for a key authorization (RFC 8555 §8.4)."""
    return b64u(hashlib.sha256(key_authorization.encode()).digest())


def validate_dns01(domain, expected_key_auth, timeout=10):
    """Query _acme-challenge.<domain> TXT and confirm a record equals
    base64url(sha256(keyAuth)). Returns (ok, detail). Uses `dig` (bind-utils)."""
    expected = dns01_txt_value(expected_key_auth)
    name = f"_acme-challenge.{domain}"
    try:
        out = subprocess.run(["dig", "+short", "TXT", name],
                             capture_output=True, text=True, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return False, f"DNS query failed: {e}"
    if out.returncode != 0:
        return False, "DNS query error"
    # `dig +short TXT` returns quoted values, one per line (possibly split into
    # quoted chunks that concatenate); strip quotes/whitespace and compare.
    values = [ln.replace('" "', '').strip().strip('"')
              for ln in out.stdout.splitlines() if ln.strip()]
    if expected in values:
        return True, "valid"
    return False, "no matching _acme-challenge TXT record"


# --------------------------------------------------------------------------
# CSR / cert helpers
# --------------------------------------------------------------------------
def cert_der_to_pem(der):
    """A DER certificate (e.g. an ACME revoke request's base64url cert) -> PEM."""
    out = subprocess.run(["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
                         input=der, capture_output=True)
    if out.returncode != 0:
        raise AcmeServerError("could not parse certificate (DER->PEM)", "malformed")
    return out.stdout.decode()
def csr_der_b64u_to_pem(csr_b64u):
    """ACME finalize sends the CSR as base64url DER; convert to PEM."""
    der = b64u_decode(csr_b64u)
    out = subprocess.run(["openssl", "req", "-inform", "DER", "-outform", "PEM"],
                         input=der, capture_output=True)
    if out.returncode != 0:
        raise AcmeServerError("could not parse finalize CSR", "badCSR")
    return out.stdout.decode()


def csr_dns_names(csr_pem):
    """DNS names (SAN + hostname-ish CN) in a CSR, lowercased."""
    txt = subprocess.run(["openssl", "req", "-noout", "-text"],
                         input=csr_pem, capture_output=True, text=True).stdout
    names = set()
    san = re.search(r"Subject Alternative Name:\s*\n\s*(.+)", txt)
    if san:
        for part in san.group(1).split(","):
            part = part.strip()
            if part.lower().startswith("dns:"):
                names.add(part[4:].strip().lower())
    cn = re.search(r"Subject:.*?CN\s*=\s*([^,/\n]+)", txt)
    if cn:
        c = cn.group(1).strip().lower()
        if "." in c and " " not in c:
            names.add(c)
    return names


def new_id():
    """Opaque id for accounts/orders/authzs/challenges (URL path component)."""
    return base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")
