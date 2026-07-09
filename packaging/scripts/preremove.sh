#!/bin/bash
# Certheim RPM pre-remove scriptlet.
#
# The systemd units live at their live paths (placed by certheim-setup, not
# owned by this package), so on a full erase we stop and disable them here to
# release :5002 and stop the timers. $1 is the count of package versions that
# will remain after this transaction: 0 = erase (act), >=1 = upgrade (leave the
# running service alone; the new code is rolled by re-running certheim-setup).
set -e

if [ "$1" = "0" ]; then
    systemctl disable --now certheim-api.service 2>/dev/null || true
    for t in certheim-expiry-warn certheim-auto-renew certheim-deliver certheim-doctor; do
        systemctl disable --now "$t.timer" 2>/dev/null || true
    done
fi
exit 0
