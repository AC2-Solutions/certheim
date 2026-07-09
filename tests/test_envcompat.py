"""Phase-1 rename shim: CERTHEIM_* / legacy CSR_* / CERTINEL_* dual-read."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import envcompat


def _clean(*names):
    for n in names:
        os.environ.pop(n, None)


def test_legacy_name_reads_legacy_value():
    _clean("CERTHEIM_DB_PATH", "CSR_DB_PATH")
    os.environ["CSR_DB_PATH"] = "/legacy/db"
    assert envcompat.getenv("CSR_DB_PATH") == "/legacy/db"
    _clean("CSR_DB_PATH")


def test_canonical_wins_over_legacy():
    os.environ["CSR_DB_PATH"] = "/legacy/db"
    os.environ["CERTHEIM_DB_PATH"] = "/new/db"
    assert envcompat.getenv("CSR_DB_PATH") == "/new/db"
    assert envcompat.getenv("CERTHEIM_DB_PATH") == "/new/db"
    _clean("CSR_DB_PATH", "CERTHEIM_DB_PATH")


def test_canonical_name_falls_back_to_legacy():
    _clean("CERTHEIM_CONTAINER", "CERTINEL_CONTAINER")
    os.environ["CERTINEL_CONTAINER"] = "1"
    assert envcompat.getenv("CERTHEIM_CONTAINER") == "1"
    _clean("CERTINEL_CONTAINER")


def test_certinel_prefix_maps_too():
    _clean("CERTHEIM_RELEASE", "CERTINEL_RELEASE")
    os.environ["CERTHEIM_RELEASE"] = "yes"
    assert envcompat.getenv("CERTINEL_RELEASE") == "yes"
    _clean("CERTHEIM_RELEASE")


def test_namespaces_do_not_cross():
    # CSR_X must never be satisfied by CERTINEL_X (distinct legacy namespaces)
    _clean("CSR_FOO_X", "CERTHEIM_FOO_X")
    os.environ["CERTINEL_FOO_X"] = "wrong"
    assert envcompat.getenv("CSR_FOO_X", "dflt") == "dflt"
    _clean("CERTINEL_FOO_X")


def test_default_and_unprefixed():
    assert envcompat.getenv("NO_SUCH_VAR_ZZZ", "d") == "d"
    os.environ["PLAIN_VAR"] = "p"
    assert envcompat.getenv("PLAIN_VAR") == "p"
    _clean("PLAIN_VAR")


def test_cap_prefix_concat():
    _clean("CERTHEIM_CAP_ACME_SERVER", "CSR_CAP_ACME_SERVER")
    os.environ["CERTHEIM_CAP_ACME_SERVER"] = "1"
    assert envcompat.getenv("CSR_CAP_ACME_SERVER") == "1"
    _clean("CERTHEIM_CAP_ACME_SERVER")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn(); print(f"  ok {name}")
    print("all envcompat tests pass")
