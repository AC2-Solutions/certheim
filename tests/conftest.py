"""Edition-aware test gating.

The codebase ships as stacked build editions (community < commercial < government);
a lower edition physically omits higher-tier modules, and the build-edition ceiling
denies higher-tier capabilities even under a license. Tests that exercise a
higher tier are therefore meaningless (and would error on the missing module) in a
lower build, so they're marked @pytest.mark.tier(N) and skipped when this build's
edition rank is below N.  1 = commercial, 2 = government.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import build_mode  # noqa: E402
import pytest  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "tier(n): minimum build edition rank required (1=commercial, 2=government)")


def pytest_collection_modifyitems(config, items):
    rank = build_mode.edition_rank()
    for item in items:
        m = item.get_closest_marker("tier")
        if m and rank < m.args[0]:
            item.add_marker(pytest.mark.skip(
                reason=f"needs build edition tier >= {m.args[0]} (this build rank={rank}, EDITION={build_mode.EDITION})"))
