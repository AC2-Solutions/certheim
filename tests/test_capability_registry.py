"""Capability-registry guard.

`is_entitled()` returns True for any key that is not in LICENSED_CAPABILITIES —
unlicensed keys are core features. That default is intentional, but it means a
premium capability nobody remembered to register would ship **unlocked**, and
nothing would fail: the feature simply works for everyone.

These tests make that impossible to do by accident. Every capability key the
code actually asks about must be classified exactly once — licensed, explicitly
free, or an alias of another key. A new premium feature whose key is missing
from the tier sets fails here instead of shipping open.
"""
import pathlib
import re
import sys

import pytest

# Deliberately NOT tier-marked: this guard must run in every edition's build,
# because each edition has its own provider set and its own chance to ship a
# premium key unclassified.

BACKEND = pathlib.Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND))

import capabilities as C  # noqa: E402

# is_entitled("x.y") / available("x.y") / status("x.y") and module-level CAP = "x.y"
_CALL = re.compile(r'(?:is_entitled|available|status)\(\s*["\']([a-z0-9_]+\.[a-z0-9_.]+)["\']')
_CAPCONST = re.compile(r'^CAP\s*=\s*["\']([a-z0-9_.]+)["\']', re.M)


def _classified(key):
    """Classified = licensed here, explicitly free, an alias, or a documented
    higher-tier key this edition omits from its catalog on purpose."""
    return (key in C.LICENSED_CAPABILITIES
            or key in C.FREE_CAPABILITIES
            or key in C.CAPABILITY_EQUIVALENTS
            or key in C.HIGHER_TIER_REFERENCES)


def _static_keys():
    keys = set()
    for f in sorted(BACKEND.glob("*.py")):
        text = f.read_text()
        keys |= set(_CALL.findall(text))
        keys |= set(_CAPCONST.findall(text))
    # Drop dynamic prefixes: `is_entitled("ca.signing." + backend)` leaves the
    # literal "ca.signing." behind. The provider tests below cover those families
    # properly, against the registry of whichever build is running.
    return {k for k in keys if not k.endswith(".")}


def test_every_referenced_key_is_classified():
    unclassified = sorted(k for k in _static_keys() if not _classified(k))
    assert not unclassified, (
        "these capability keys are referenced in code but classified nowhere, so "
        "is_entitled() returns True for them in every edition — register them in a "
        "tier set (premium) or FREE_CAPABILITIES (core): " + ", ".join(unclassified))


def test_every_signing_backend_key_is_classified():
    """`is_entitled("ca.signing." + backend)` is built at run time, so the static
    scan can't see it. Check the provider registry of THIS build directly."""
    import sign
    keys = ["ca.signing." + p for p in sign.PROVIDERS]
    unclassified = sorted(k for k in keys if not _classified(k))
    assert not unclassified, (
        "signing backends whose availability check would fail open: "
        + ", ".join(unclassified))


def test_every_delivery_provider_key_is_classified():
    """Same for `is_entitled("delivery." + provider)`. Skipped on Community,
    which ships no delivery module."""
    deliver = pytest.importorskip("deliver")
    keys = ["delivery." + p for p in deliver.PROVIDERS]
    unclassified = sorted(k for k in keys if not _classified(k))
    assert not unclassified, (
        "delivery providers whose availability check would fail open: "
        + ", ".join(unclassified))


def test_free_and_licensed_do_not_overlap():
    both = C.FREE_CAPABILITIES & C.LICENSED_CAPABILITIES
    assert not both, f"keys claimed as both free and licensed: {sorted(both)}"


def test_equivalents_point_at_real_keys():
    for alias, target in C.CAPABILITY_EQUIVALENTS.items():
        assert _classified(target), (
            f"{alias} aliases {target}, which is itself unclassified")
        assert alias not in C.LICENSED_CAPABILITIES, (
            f"{alias} is both an alias and a licensed key — pick one")


def test_alias_resolves_to_its_target_entitlement():
    """An alias must answer exactly as its target does, so a backend can't look
    available and then refuse inside the signer."""
    for alias, target in C.CAPABILITY_EQUIVALENTS.items():
        assert C.is_entitled(alias) == C.is_entitled(target), (
            f"{alias} and {target} disagree — availability and enforcement would diverge")
