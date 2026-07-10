"""Environment-variable access for Certheim.

Historically this module was a rename compatibility shim: every configuration
variable was readable under BOTH its canonical spelling (CERTHEIM_*) and its
legacy spelling (CSR_* / CERTINEL_*), with the canonical name winning. That
dual-read was removed in Phase 5 of the certinel->certheim rename, once every
install's env file, the container image's baked env, and the entrypoint had
moved to the canonical CERTHEIM_* spelling. Only the canonical name is read
now; the thin getenv()/candidates() API is kept so call sites don't change.

Stdlib-only on purpose: this module is imported by build_mode/capabilities,
which the installer runs before any venv exists.
"""

import os

_PREFIX_NEW = "CERTHEIM_"


def candidates(name):
    """The env-var name(s) that may satisfy `name`.

    The certinel->certheim dual-read was dropped in Phase 5, so this is just
    the name itself; kept as a function to preserve a stable API for callers.
    """
    return [name]


def getenv(name, default=None):
    """os.environ.get(name, default).

    The certinel->certheim rename dual-read shim was removed in Phase 5; only
    the canonical CERTHEIM_* spelling is read.
    """
    v = os.environ.get(name)
    return v if v is not None else default
