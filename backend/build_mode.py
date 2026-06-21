"""build_mode.py - development build vs. hardened release build.

Certinel ships as source the customer runs on a box they control, so no license
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
