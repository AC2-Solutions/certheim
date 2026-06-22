# Certinel container image (Podman/Buildah/Docker).
#
# One Containerfile, two bases via the PYBASE build arg:
#   * default  -> RHEL UBI 9 + Python 3.12  (FIPS-capable, for gov/regulated)
#   * slim     -> docker.io/library/python:3.12-slim  (smaller, general use)
# The package-install line below works on both (microdnf or apt).
#
#   buildah bud -t certinel:ubi  .
#   buildah bud -t certinel:slim --build-arg PYBASE=docker.io/library/python:3.12-slim .
#
# Runs container-mode (CERTINEL_CONTAINER=1): no sudo helper, mTLS at the ingress.
# Roles are selected via the entrypoint: web (default) | migrate | cron <task>.
ARG PYBASE=registry.access.redhat.com/ubi9/python-312:latest

# ---- builder: resolve the Python dependencies into a venv -------------------
FROM ${PYBASE} AS builder
USER 0
WORKDIR /build
COPY requirements.txt requirements-postgres.txt ./
# psycopg is bundled so the same image serves SQLite or PostgreSQL.
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -U pip \
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
COPY backend/  /opt/certinel/
COPY VERSION   /opt/certinel/VERSION
COPY helper/   /opt/certinel/helper/
COPY frontend/ /var/www/csr/
COPY container/entrypoint.sh /usr/local/bin/entrypoint.sh

# Create a non-root user (uid/gid 10001) and own the app + writable data paths.
# useradd ships on both bases (UBI + Debian slim); fall back to numeric-only if
# absent. The chown runs BEFORE the VOLUME declaration so a fresh named volume
# (Docker/Podman) inherits 10001 ownership; on k8s set podSecurityContext.fsGroup.
RUN set -e; \
    chmod 0750 /opt/certinel/helper/certinel_helper.sh; \
    chmod 0755 /usr/local/bin/entrypoint.sh; \
    mkdir -p /var/lib/certinel /var/opt/certinel/issued /var/opt/certinel/requests \
             /var/opt/certinel/private /etc/certinel; \
    groupadd -g 10001 certinel 2>/dev/null || true; \
    useradd -u 10001 -g 10001 -M -d /opt/certinel -s /sbin/nologin certinel 2>/dev/null \
      || useradd -u 10001 -g 10001 -d /opt/certinel certinel 2>/dev/null || true; \
    chown -R 10001:10001 /opt/certinel /var/lib/certinel /var/opt/certinel /etc/certinel

ENV PATH=/opt/venv/bin:$PATH \
    CERTINEL_CONTAINER=1 \
    CSR_DB_PATH=/var/lib/certinel/jobs.db \
    CSR_HELPER_PATH=/opt/certinel/helper/certinel_helper.sh \
    CSR_ISSUED_DIR=/var/opt/certinel/issued \
    CERTINEL_PORT=5002

WORKDIR /opt/certinel
EXPOSE 5002
# The /var/lib/certinel (SQLite) and /var/opt/certinel (issued/keys) paths are
# the persistent volumes a deployment mounts.
VOLUME ["/var/lib/certinel", "/var/opt/certinel"]
# Default to the non-root user (Docker Scout: "default non-root user"). gunicorn
# binds :5002 (>1024, unprivileged); the helper runs sudo-less in container mode.
USER 10001
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["web"]
