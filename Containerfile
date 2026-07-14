# Certheim container image (Podman/Buildah/Docker).
#
# One Containerfile, two bases via the PYBASE build arg:
#   * default  -> RHEL UBI 9 + Python 3.12  (FIPS-capable, for gov/regulated)
#   * slim     -> docker.io/library/python:3.12-slim  (smaller, general use)
# The package-install line below works on both (microdnf or apt).
#
#   buildah bud -t certheim:ubi  .
#   buildah bud -t certheim:slim --build-arg PYBASE=docker.io/library/python:3.12-slim .
#
# Runs container-mode (CERTHEIM_CONTAINER=1): no sudo helper, mTLS at the ingress.
# Roles are selected via the entrypoint: web (default) | migrate | cron <task>.
ARG PYBASE=registry.access.redhat.com/ubi9/python-312-minimal:latest

# ---- builder: resolve the Python dependencies into a venv -------------------
FROM ${PYBASE} AS builder
USER 0
WORKDIR /build
COPY requirements.txt requirements-postgres.txt ./
# psycopg is bundled so the same image serves SQLite or PostgreSQL.
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -U pip setuptools \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt -r requirements-postgres.txt

# ---- runtime ---------------------------------------------------------------
FROM ${PYBASE} AS runtime
USER 0
# openssl (all crypto/parse calls shell out to it) + optional clients used by
# some signing/delivery backends (SSH delivery, ACME DNS-01). Portable across
# UBI (microdnf) and Debian (apt).
RUN set -e; \
    for pm in microdnf dnf yum; do command -v $pm >/dev/null 2>&1 && PM=$pm && break; done; \
    if [ -n "$PM" ]; then \
        $PM install -y openssl; ( $PM install -y openssh-clients bind-utils || true ); $PM clean all || true; \
    elif command -v apt-get >/dev/null 2>&1; then \
        apt-get update; apt-get install -y --no-install-recommends openssl; \
        ( apt-get install -y --no-install-recommends openssh-client dnsutils || true ); \
        rm -rf /var/lib/apt/lists/*; \
    else echo "no supported package manager in base image"; exit 1; fi

COPY --from=builder /opt/venv /opt/venv
COPY backend/  /opt/certheim/
COPY VERSION   /opt/certheim/VERSION
# Per-edition version files. _read_version() prefers editions/<edition>.version
# (selected by build_mode.EDITION) and only falls back to the root VERSION, which
# is the community base line. Without this, a Commercial/Government image has no
# editions/ dir and reports the community version (e.g. 3.23.3) instead of its
# own (e.g. commercial 3.61.4). Each branch carries only its own .version, so
# the community image still resolves community.version.
COPY editions/ /opt/certheim/editions/
COPY helper/   /opt/certheim/helper/
COPY frontend/ /var/www/csr/
COPY container/entrypoint.sh /usr/local/bin/entrypoint.sh

# Cache-bust: stamp a content hash onto the JS/CSS refs in the baked index.html
# so browsers fetch fresh assets after every image change (the source keeps bare
# refs; the served copy is stamped once at build). Mirrors deploy.sh for VMs. The
# nginx sidecar serves this stamped copy via the copy-frontend init container.
RUN set -e; \
    stamp="$(cat /var/www/csr/app.*.js /var/www/csr/app.css | sha256sum | cut -c1-10)"; \
    sed -i -E "s#(href=\"app\.css)(\?v=[0-9a-f]+)?\"#\1?v=${stamp}\"#; \
               s#(src=\"app\.[0-9][^\"?]*\.js)(\?v=[0-9a-f]+)?\"#\1?v=${stamp}\"#g" \
        /var/www/csr/index.html; \
    echo "certheim: stamped assets ?v=${stamp}"


# Create a non-root user (uid/gid 10001) and own the app + writable data paths.
# useradd ships on both bases (UBI + Debian slim); fall back to numeric-only if
# absent. The chown runs BEFORE the VOLUME declaration so a fresh named volume
# (Docker/Podman) inherits 10001 ownership; on k8s set podSecurityContext.fsGroup.
RUN set -e; \
    chmod 0750 /opt/certheim/helper/certheim_helper.sh; \
    chmod 0755 /usr/local/bin/entrypoint.sh; \
    mkdir -p /var/lib/certheim /var/opt/certheim/issued /var/opt/certheim/requests \
             /var/opt/certheim/private /etc/certheim; \
    groupadd -g 10001 certheim 2>/dev/null || true; \
    useradd -u 10001 -g 10001 -M -d /opt/certheim -s /sbin/nologin certheim 2>/dev/null \
      || useradd -u 10001 -g 10001 -d /opt/certheim certheim 2>/dev/null || true; \
    chown -R 10001:10001 /opt/certheim /var/lib/certheim /var/opt/certheim /etc/certheim

# Canonical CERTHEIM_* env (rename Phase 5). Only CERTHEIM_CONTAINER/PORT are
# baked. The DB/helper/issued paths are intentionally NOT baked: the app's
# built-in _ENV_DEFAULTS supplies the identical values, and leaving them unset
# in the image lets container/entrypoint.sh auto-detect a legacy volume mounted
# at the old /var/lib/certinel path (its guard treats any baked CERTHEIM_DB_PATH
# as an explicit override and would skip detection).
ENV PATH=/opt/venv/bin:$PATH \
    CERTHEIM_CONTAINER=1 \
    CERTHEIM_PORT=5002

WORKDIR /opt/certheim
EXPOSE 5002
# The /var/lib/certheim (SQLite) and /var/opt/certheim (issued/keys) paths are
# the persistent volumes a deployment mounts.
VOLUME ["/var/lib/certheim", "/var/opt/certheim"]
# Default to the non-root user (Docker Scout: "default non-root user"). gunicorn
# binds :5002 (>1024, unprivileged); the helper runs sudo-less in container mode.
USER 10001
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["web"]
