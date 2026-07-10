"""Phase-5: the certinel->certheim rename dual-read shim has been removed.
envcompat.getenv() now reads ONLY the exact (canonical) name it is given."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import envcompat


def _clean(*names):
    for n in names:
        os.environ.pop(n, None)


def test_reads_exact_name():
    _clean("CERTHEIM_DB_PATH")
    os.environ["CERTHEIM_DB_PATH"] = "/new/db"
    assert envcompat.getenv("CERTHEIM_DB_PATH") == "/new/db"
    _clean("CERTHEIM_DB_PATH")


def test_canonical_does_not_fall_back_to_legacy():
    # A legacy CSR_/CERTINEL_ value must NOT satisfy the canonical name anymore.
    _clean("CERTHEIM_DB_PATH", "CSR_DB_PATH", "CERTHEIM_CONTAINER", "CERTINEL_CONTAINER")
    os.environ["CSR_DB_PATH"] = "/legacy/db"
    os.environ["CERTINEL_CONTAINER"] = "1"
    assert envcompat.getenv("CERTHEIM_DB_PATH", "dflt") == "dflt"
    assert envcompat.getenv("CERTHEIM_CONTAINER", "0") == "0"
    _clean("CSR_DB_PATH", "CERTINEL_CONTAINER")


def test_legacy_name_reads_only_itself():
    # Passing a legacy name reads that literal var only (no mapping to CERTHEIM_*).
    _clean("CSR_DB_PATH", "CERTHEIM_DB_PATH")
    os.environ["CERTHEIM_DB_PATH"] = "/new/db"
    assert envcompat.getenv("CSR_DB_PATH", "dflt") == "dflt"
    _clean("CERTHEIM_DB_PATH")


def test_candidates_is_identity():
    assert envcompat.candidates("CERTHEIM_DB_PATH") == ["CERTHEIM_DB_PATH"]
    assert envcompat.candidates("CSR_DB_PATH") == ["CSR_DB_PATH"]


def test_default_and_plain_var():
    assert envcompat.getenv("NO_SUCH_VAR_ZZZ", "d") == "d"
    os.environ["PLAIN_VAR"] = "p"
    assert envcompat.getenv("PLAIN_VAR") == "p"
    _clean("PLAIN_VAR")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn(); print(f"  ok {name}")
    print("all envcompat tests pass")
