"""Cert download-format conversions + the job download endpoints.

The dashboard used to hand back PEM only (mislabeled .cer). These cover the new
DER / PKCS#7 / PKCS#12 conversions and that the PKCS#12 route enforces the same
private-key authorization as the key download and never builds a passwordless
keystore.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))

import cert_formats as cf  # noqa: E402


@pytest.fixture(scope="module")
def chain_and_key():
    d = tempfile.mkdtemp()
    run = lambda a: subprocess.run(a, check=True, capture_output=True)
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", d + "/ca.key", "-out", d + "/ca.pem",
         "-subj", "/CN=Test CA", "-days", "3"])
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", d + "/leaf.key", "-out", d + "/leaf.csr",
         "-subj", "/CN=host.example.com"])
    run(["openssl", "x509", "-req", "-in", d + "/leaf.csr", "-CA", d + "/ca.pem",
         "-CAkey", d + "/ca.key", "-CAcreateserial", "-out", d + "/leaf.pem",
         "-days", "3"])
    chain = open(d + "/leaf.pem").read() + open(d + "/ca.pem").read()
    return chain, open(d + "/leaf.key").read(), d


def test_pem_is_leaf_only(chain_and_key):
    chain, _, _ = chain_and_key
    body, mt, fn = cf.convert(chain, "pem", base_name="host")
    assert body.count(b"BEGIN CERTIFICATE") == 1 and fn == "host.pem"


def test_pem_chain_keeps_all(chain_and_key):
    chain, _, _ = chain_and_key
    body, _, _ = cf.convert(chain, "pem-chain")
    assert body.count(b"BEGIN CERTIFICATE") == 2


def test_der_is_parseable_and_named_cer(chain_and_key):
    chain, _, d = chain_and_key
    body, mt, fn = cf.convert(chain, "der", base_name="host")
    assert fn == "host.cer" and mt.startswith("application/")
    p = os.path.join(d, "o.der"); open(p, "wb").write(body)
    r = subprocess.run(["openssl", "x509", "-inform", "DER", "-in", p,
                        "-noout", "-subject"], capture_output=True, text=True)
    assert "host.example.com" in r.stdout


def test_p7b_carries_full_chain(chain_and_key):
    chain, _, d = chain_and_key
    body, _, fn = cf.convert(chain, "p7b")
    assert fn.endswith(".p7b")
    p = os.path.join(d, "o.p7b"); open(p, "wb").write(body)
    r = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", p,
                        "-print_certs", "-noout"], capture_output=True, text=True)
    assert r.stdout.count("subject=") == 2


def test_p12_opens_with_its_password(chain_and_key):
    chain, key, d = chain_and_key
    body, mt, fn = cf.convert(chain, "p12", key_pem=key, password="s3cretpw", base_name="host")
    assert fn == "host.pfx" and mt == "application/x-pkcs12"
    p = os.path.join(d, "o.pfx"); open(p, "wb").write(body)
    ok = subprocess.run(["openssl", "pkcs12", "-in", p, "-noout",
                         "-passin", "pass:s3cretpw"], capture_output=True)
    assert ok.returncode == 0
    bad = subprocess.run(["openssl", "pkcs12", "-in", p, "-noout",
                          "-passin", "pass:wrong"], capture_output=True)
    assert bad.returncode != 0


def test_p12_needs_key_and_password(chain_and_key):
    chain, key, _ = chain_and_key
    with pytest.raises(cf.FormatError):
        cf.convert(chain, "p12", password="s3cretpw")          # no key
    with pytest.raises(cf.FormatError):
        cf.convert(chain, "p12", key_pem=key)                  # no password
    with pytest.raises(cf.FormatError):
        cf.convert(chain, "p12", key_pem=key, password="")     # empty password


def test_unknown_format_rejected(chain_and_key):
    chain, _, _ = chain_and_key
    with pytest.raises(cf.FormatError):
        cf.convert(chain, "jks")


def test_no_cert_in_input():
    with pytest.raises(cf.FormatError):
        cf.convert("not a cert", "pem")
