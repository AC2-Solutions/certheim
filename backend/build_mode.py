"""build_mode.py - development build vs. hardened release build.

Certheim ships as source the customer runs on a box they control, so no license
check can ever be made tamper-PROOF (root can edit the bytes). What we CAN do is
keep the *convenience bypasses* out of release artifacts, so a downstream
operator can't unlock paid editions just by exporting an environment variable.

Two insecure-but-handy overrides exist for development and evaluation:

  * CSR_LICENSE_PUBKEY  - swap the embedded vendor trust anchor (sign your own
                          licenses against a key you control)
  * CSR_ENTITLEMENTS=*  - grant every licensed capability with no license at all

Both are honored ONLY in a development build. A release build is stamped by the
release pipeline (release.sh flips RELEASE_BUILD below) or marked at package time
with CERTINEL_RELEASE=1; from then on the overrides are inert no matter what
environment a downstream operator sets.

Note the deliberate asymmetry: the environment can only ever make a build *more*
locked (mark it a release), never less. Loosening a release build back into
"trust my own key / grant everything" requires editing THIS file in source - the
irreducible floor that exists for any self-hosted product. The point is not to
make theft impossible (it can't be); it's to ensure that bypassing the license
is an unmistakable act of source tampering, not a documented env var - which is
what makes it cleanly actionable under copyright / anti-circumvention law.
"""
import os

# The release pipeline (tools/release.sh) flips this to True when it stamps a
# release artifact. A plain source checkout is a development build.
RELEASE_BUILD = False

# Product edition of THIS build. The Community build physically OMITS the premium
# modules (ca_providers, acme_dns, acme_server, routes_acme, deliver,
# routes_deliver, renew, slack_listener); the free ACME *client* (acme_client.py:
# RFC 8555 + HTTP-01 + internal DNS-01/rfc2136) DOES ship with Community — only
# the cloud DNS-01 solvers (acme_dns) and the ACME server stay premium. This
# marker lets the surviving core
# force every licensed capability OFF regardless of any license file, and lets
# the UI render those features grayed-out as upsell. The licensed (Full) build
# sets EDITION = "full" — no license can turn a Community BUILD into a paid one,
# because the paid code simply isn't present. Upgrading = re-deploying with the
# Full codebase (an additive migration), not flipping a flag.
EDITION = "community"


def is_community_build():
    """True when this build ships without the premium code (the free edition).

    Unlike a license check, this can't be bypassed by editing a license file or
    an env var — the premium modules aren't in the artifact to begin with."""
    return EDITION == "community"


# Build editions form a ladder: each higher build physically contains everything
# below it plus its own tier. The branch sets EDITION; this rank is the hard
# CEILING on what features the build can run, regardless of any license:
#   community(0)  -> no premium code at all
#   commercial(1) -> + the commercial premium modules
#   government(2) -> + the government pack (CAC / mTLS, public-sector profiles)
#   full(3)       -> developer build, everything (== government, dev overrides on)
_EDITION_RANK = {"community": 0, "commercial": 1, "government": 2, "full": 3}


def edition_rank():
    return _EDITION_RANK.get(EDITION, 3)


def build_includes_tier(tier):
    """True when this build physically contains a capability of the given tier
    (1 = commercial, 2 = government). The license still has to GRANT it on top —
    the build is the ceiling, the license is the key."""
    return edition_rank() >= tier


def is_release():
    """True in a hardened release build - either the baked-in stamp above, or a
    CERTINEL_RELEASE=1 marker applied at package/deploy time."""
    if RELEASE_BUILD:
        return True
    return os.environ.get("CERTINEL_RELEASE", "").strip() not in ("", "0", "false", "False")


def dev_overrides_allowed():
    """Whether the insecure dev/eval env overrides are honored.

    False in a release build: the embedded vendor key is then the ONLY trust
    anchor and a valid signed license is the ONLY way to unlock paid editions.
    """
    return not is_release()


def describe():
    """Short human label for logs / the startup banner."""
    return "release" if is_release() else "development"
