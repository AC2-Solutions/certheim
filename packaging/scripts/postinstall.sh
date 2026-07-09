#!/bin/bash
# Certheim RPM post-install scriptlet.
#
# The package lays down the application source tree + an offline wheelhouse under
# /usr/share/certheim and the `certheim-setup` command. Configuration (FQDN, TLS
# mode, nginx, venv build, service start) is DEFERRED to certheim-setup because
# it needs host-specific choices — so we intentionally do NOT start any service
# here. We only refresh systemd's view and tell the operator what to run next.
set -e

systemctl daemon-reload 2>/dev/null || true

cat <<'EOF'

  Certheim is installed. To configure and start it on this host, run:

      sudo certheim-setup

  This picks the FQDN/TLS mode, provisions nginx, builds the service venv from
  the bundled offline wheelhouse, and starts the certheim-api systemd service.

  Unattended install (every prompt has an env override):

      sudo FQDN=cert.example.com ASSUME_DEFAULTS=yes certheim-setup

  Apply a Commercial/Government license with LICENSE_FILE=/path/to/license.

EOF
exit 0
