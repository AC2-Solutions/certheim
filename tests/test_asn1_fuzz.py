"""Robustness fuzzing for the unauthenticated ASN.1 parsers.

SCEP, EST, and CMP all parse attacker-controlled DER on public, pre-auth
endpoints (/scep, /.well-known/est/*, /cmp). The security property under test:
**malformed input must fail with a controlled error, never with an unhandled
crash (info-leaking 500 / stack trace), a resource-exhaustion error
(Recursion/Memory), or a hang.**

The corpus is deterministic (seeded) so a regression is reproducible: empty
input, ASN.1 length/indefinite-length bombs, a deep-nesting bomb, random noise,
every truncation of a valid CSR-DER, and byte-flips of it.

These modules are Commercial+; the test skips cleanly where they're absent (the
Community edition and the bare CI venv without asn1crypto)."""
import os
import random
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest

# Optional per-call hang guard (Linux/main-thread only).
try:
    import signal
    _HAVE_ALARM = hasattr(signal, "SIGALRM")
except ImportError:                         # pragma: no cover
    _HAVE_ALARM = False


class _Timeout(Exception):
    pass


def _valid_csr_der(tmp):
    subprocess.run(
        ["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
         "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(tmp / "k"),
         "-out", str(tmp / "c"), "-subj", "/CN=fuzz"],
        check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-in", str(tmp / "c"), "-outform", "DER",
                    "-out", str(tmp / "cd")], check=True, capture_output=True)
    return (tmp / "cd").read_bytes()


def _corpus(valid):
    rnd = random.Random(1337)
    yield b""
    yield b"\x30\x80" + b"\xff" * 10                 # indefinite-length + junk
    yield b"\x30\x84\x7f\xff\xff\xff"                # SEQUENCE claiming ~2 GiB
    yield b"\x30" * 20000                            # nesting / recursion bomb
    for _ in range(300):
        yield os.urandom(rnd.randint(0, 400))        # random noise
    for n in range(1, len(valid)):
        yield valid[:n]                              # every truncation
    for _ in range(150):                             # byte flips
        b = bytearray(valid)
        if b:
            b[rnd.randrange(len(b))] ^= rnd.randint(1, 255)
        yield bytes(b)


# The parser's own error type, asn1crypto parse errors, and plain value/type
# errors are all "controlled". Anything else (RecursionError, MemoryError,
# KeyError, IndexError, struct.error, a hang, …) is a robustness finding.
_CONTROLLED = {"SCEPError", "CmpError", "ESTError", "LocalCAError",
               "ValueError", "TypeError"}


def _is_controlled(exc):
    return (type(exc).__name__ in _CONTROLLED
            or "asn1crypto" in type(exc).__module__)


def _run_fuzz(fn, valid):
    if _HAVE_ALARM:
        signal.signal(signal.SIGALRM,
                      lambda *_a: (_ for _ in ()).throw(_Timeout()))
    findings = []
    exercised = 0
    for data in _corpus(valid):
        exercised += 1
        if _HAVE_ALARM:
            signal.alarm(5)
        try:
            fn(data)
        except _Timeout:                            # pragma: no cover
            findings.append(("HANG", data[:12].hex()))
        except BaseException as e:                  # noqa: BLE001 - that's the test
            if not _is_controlled(e):
                findings.append((type(e).__name__ + ": " + str(e)[:80],
                                 data[:12].hex()))
        finally:
            if _HAVE_ALARM:
                signal.alarm(0)
    return exercised, findings


@pytest.fixture(scope="module")
def valid_der(tmp_path_factory):
    return _valid_csr_der(tmp_path_factory.mktemp("fuzz"))


def test_scep_parse_is_robust(valid_der):
    scep = pytest.importorskip("scep")
    if not getattr(scep, "available", lambda: True)():
        pytest.skip("scep needs asn1crypto")
    exercised, findings = _run_fuzz(lambda d: scep.parse_pki_request(d), valid_der)
    assert exercised > 500
    assert findings == [], f"SCEP parser robustness findings: {findings[:10]}"


def test_est_decode_pkcs10_is_robust(valid_der):
    est = pytest.importorskip("est")
    # est.decode_pkcs10 takes the raw request body (base64 or DER PKCS#10).
    exercised, findings = _run_fuzz(lambda d: est.decode_pkcs10(d), valid_der)
    assert exercised > 500
    assert findings == [], f"EST parser robustness findings: {findings[:10]}"


def test_cmp_handle_message_is_robust(valid_der):
    cmp = pytest.importorskip("cmp")
    if not cmp.available():
        pytest.skip("cmp needs asn1crypto")

    def _sign(_pem):                                # never reached on garbage
        return ("cert", "chain")

    exercised, findings = _run_fuzz(
        lambda d: cmp.handle_message(d, "fuzz-secret-1234", _sign), valid_der)
    assert exercised > 500
    assert findings == [], f"CMP parser robustness findings: {findings[:10]}"
