"""cert_formats.py - convert an issued PEM cert (+ chain, + optional key) into
the download formats operators actually ask for.

The dashboard has only ever handed back PEM. Windows/IIS, Java keystores, and
older appliances want DER, PKCS#7, or a password-protected PKCS#12 bundle.
Every conversion shells `openssl` (already a hard dependency of the signer),
so nothing new is pulled in. Pure w.r.t. the DB: callers pass the material in.
"""
import os
import re
import shutil
import subprocess
import tempfile

# format -> (mimetype, filename extension, needs_private_key)
FORMATS = {
    "pem":       ("application/x-pem-file", "pem", False),   # leaf only
    "pem-chain": ("application/x-pem-file", "pem", False),   # leaf + issuers
    "der":       ("application/pkcs8",      "cer", False),   # leaf, binary DER
    "p7b":       ("application/x-pkcs7-certificates", "p7b", False),  # chain, DER
    "p12":       ("application/x-pkcs12",   "pfx", True),    # leaf+chain+key
}

_PEM_CERT = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


class FormatError(ValueError):
    """A conversion could not be performed (bad input, or key required)."""


def _split(chain_pem):
    """Return [leaf_pem, *issuer_pems] from a PEM bundle."""
    certs = _PEM_CERT.findall(chain_pem or "")
    if not certs:
        raise FormatError("no PEM certificate found")
    return [c + "\n" for c in certs]


def _run(args, **kw):
    p = subprocess.run(args, capture_output=True, **kw)
    if p.returncode != 0:
        raise FormatError(p.stderr.decode("utf-8", "replace")[:200] or "openssl failed")
    return p.stdout


def convert(chain_pem, fmt, key_pem=None, password=None, base_name="certificate"):
    """(bytes, mimetype, filename) for the requested format.

    - pem:        the leaf certificate, PEM
    - pem-chain:  leaf + issuers, PEM (the full bundle as stored)
    - der:        the leaf certificate, binary DER (.cer)
    - p7b:        the whole chain as a PKCS#7, DER (.p7b)
    - p12:        leaf + chain + private key, PKCS#12 (.pfx); needs key_pem and
                  a non-empty password (never produce an unencrypted keystore).
    """
    fmt = (fmt or "pem").lower()
    if fmt not in FORMATS:
        raise FormatError("unknown format %r (want one of %s)"
                          % (fmt, ", ".join(sorted(FORMATS))))
    mimetype, ext, needs_key = FORMATS[fmt]
    certs = _split(chain_pem)
    leaf = certs[0]
    fname = "%s.%s" % (base_name, ext)

    if fmt == "pem":
        return leaf.encode(), mimetype, fname
    if fmt == "pem-chain":
        return "".join(certs).encode(), mimetype, fname

    d = tempfile.mkdtemp(prefix="certheim-fmt-")
    try:
        leaf_p = os.path.join(d, "leaf.pem")
        with open(leaf_p, "w") as f:
            f.write(leaf)
        if fmt == "der":
            return _run(["openssl", "x509", "-in", leaf_p, "-outform", "DER"]), mimetype, fname
        if fmt == "p7b":
            chain_p = os.path.join(d, "chain.pem")
            with open(chain_p, "w") as f:
                f.write("".join(certs))
            return (_run(["openssl", "crl2pkcs7", "-nocrl", "-certfile", chain_p,
                          "-outform", "DER"]), mimetype, fname)
        # p12
        if not needs_key:
            raise FormatError("internal: p12 flagged keyless")
        if not key_pem:
            raise FormatError("PKCS#12 needs the private key, which is not "
                              "available for this certificate")
        if not password:
            # openssl would happily write a passwordless .p12; refuse it - an
            # unprotected keystore of a live private key is a footgun.
            raise FormatError("a password is required to build a PKCS#12 bundle")
        key_p = os.path.join(d, "key.pem")
        with open(os.open(key_p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(key_pem)
        args = ["openssl", "pkcs12", "-export", "-inkey", key_p, "-in", leaf_p,
                "-name", base_name, "-passout", "env:CH_P12_PW"]
        if len(certs) > 1:
            ca_p = os.path.join(d, "ca.pem")
            with open(ca_p, "w") as f:
                f.write("".join(certs[1:]))
            args += ["-certfile", ca_p]
        return (_run(args, env={**os.environ, "CH_P12_PW": password}),
                mimetype, fname)
    finally:
        shutil.rmtree(d, ignore_errors=True)
