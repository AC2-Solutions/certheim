#!/bin/bash
# Certheim RPM post-remove scriptlet. Refresh systemd, and on a full erase point
# the operator at the data/config left behind (deliberately preserved so an
# accidental `dnf remove` never destroys issued certs or the database).
set -e

systemctl daemon-reload 2>/dev/null || true

if [ "$1" = "0" ]; then
cat <<'EOF'

  Certheim package removed (/usr/share/certheim is gone). Runtime data and
  configuration were left in place:

      /opt/certinel        app runtime + venv (placed by certheim-setup)
      /var/opt/certinel    issued certs, generated requests
      /var/lib/certinel    database
      /etc/certinel        configuration + license pointer

  To remove them too, run the bundled uninstaller before it disappears, or
  delete the paths above by hand:

      sudo certinel-uninstall

EOF
fi
exit 0
