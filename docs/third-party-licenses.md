# Third-party licenses

Certinel bundles the following third-party open-source components. Each is used
under its own license; this inventory is provided for compliance and due
diligence. See also the top-level `NOTICE` file.

## Python dependencies (always installed)

| Component | License | Project |
|---|---|---|
| Flask | BSD-3-Clause | https://github.com/pallets/flask |
| Werkzeug | BSD-3-Clause | https://github.com/pallets/werkzeug |
| Jinja2 | BSD-3-Clause | https://github.com/pallets/jinja |
| MarkupSafe | BSD-3-Clause | https://github.com/pallets/markupsafe |
| itsdangerous | BSD-3-Clause | https://github.com/pallets/itsdangerous |
| click | BSD-3-Clause | https://github.com/pallets/click |
| blinker | MIT | https://github.com/pallets-eco/blinker |
| gunicorn | MIT | https://github.com/benoitc/gunicorn |
| importlib-metadata | Apache-2.0 | https://github.com/python/importlib_metadata |
| zipp | MIT | https://github.com/jaraco/zipp |
| packaging | Apache-2.0 OR BSD-2-Clause | https://github.com/pypa/packaging |

## Python dependencies (optional / feature-gated)

| Component | License | Enabled by | Project |
|---|---|---|---|
| psycopg[binary] | **LGPL-3.0-or-later** | PostgreSQL backend (`requirements-postgres.txt`) | https://github.com/psycopg/psycopg |
| cryptography | Apache-2.0 OR BSD-3-Clause | Sealed keystore in-process ciphers (`requirements-sealed.txt`) | https://github.com/pyca/cryptography |
| asn1crypto | MIT | SCEP / CMP enrollment (`requirements-sealed.txt`) | https://github.com/wbond/asn1crypto |

**LGPL note (psycopg):** the PostgreSQL driver is LGPL-3.0-or-later and is
included only in Postgres deployments. Certinel uses it **unmodified** as
published on PyPI and dynamically at runtime; the corresponding source and full
license text are available at the project URL above. No Certinel source is
subject to the LGPL as a result of this dynamic use.

## Runtime / base images

| Component | License | Notes |
|---|---|---|
| Red Hat UBI9 `python-312-minimal` (default base) | Red Hat UBI EULA + per-component licenses | Redistributable base image; component licenses inside the image |
| Debian `python:3.12-slim` (the `-slim` image variant) | PSF (Python) + per-package (Debian) | Alternative base for the slim images |
| CPython 3.12 | PSF License | Interpreter |
| OpenSSL 3.x | Apache-2.0 | System crypto (all hashing/HMAC/TLS/RNG + the `openssl` CLI Certinel shells out to) |
| nginx | BSD-2-Clause | Static-asset / reverse-proxy sidecar (container/k8s deployments) |

## Regenerating this inventory

The Python portion can be regenerated from the installed environment:

```bash
python3 - <<'PY'
import importlib.metadata as m
for d in sorted(m.distributions(), key=lambda d: d.name.lower()):
    md = d.metadata
    lic = md.get("License-Expression") or md.get("License") or "; ".join(
        c.split("::")[-1].strip() for c in md.get_all("Classifier", [])
        if c.startswith("License"))
    print(f"{d.name}\t{d.version}\t{lic}")
PY
```

Base-image and OpenSSL licenses are fixed by the chosen base and are listed
above; re-check them when the base image is bumped.
