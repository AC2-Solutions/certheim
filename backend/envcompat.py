"""Environment-variable compatibility shim for the certinel->certheim rename.

Phase 1 of the internal rename (docs/certheim-rename-design.md): every
configuration variable is readable under BOTH its canonical new spelling
(CERTHEIM_*) and its legacy spelling (CSR_* / CERTINEL_*), so renamed code and
un-migrated installs can coexist in any order. The canonical name wins when
both are set. Remove in Phase 5 once every install's env file is migrated.

Call sites pass whichever spelling they historically used; getenv() consults
the whole candidate set. CSR_* and CERTINEL_* are distinct legacy namespaces
that both map onto CERTHEIM_* — they are never cross-consulted.

Stdlib-only on purpose: this module is imported by build_mode/capabilities,
which the installer runs before any venv exists.
"""

import os

_PREFIX_NEW = "CERTHEIM_"
_PREFIXES_LEGACY = ("CSR_", "CERTINEL_")


def candidates(name):
    """The ordered list of env-var names that may satisfy `name`."""
    if name.startswith(_PREFIX_NEW):
        suffix = name[len(_PREFIX_NEW):]
        return [name] + [p + suffix for p in _PREFIXES_LEGACY]
    for p in _PREFIXES_LEGACY:
        if name.startswith(p):
            return [_PREFIX_NEW + name[len(p):], name]
    return [name]


def getenv(name, default=None):
    """os.environ.get() with rename dual-read; canonical CERTHEIM_* wins."""
    for c in candidates(name):
        v = os.environ.get(c)
        if v is not None:
            return v
    return default
