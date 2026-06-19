# CSR Dashboard v2.26.0

_Released 2026-06-19. 4 changes since v2.25.0._

## Features

- key-handling Phase 4c - ProtectHome=true (helper + keys off /root) (`6853512`)
  The sandbox now masks /home + /root from certinel-api and its children. Safe because the helper
  lives under /opt/certinel and keys go to the vault (only a brief /var/opt/certinel scratch).
  Runbook updated to the relocated paths.
- key-handling Phase 4b - relocate helper + key scratch off /root (`1c0f9f6`)
  Helper /root/sslcerts/scripts -> /opt/certinel/helper; KEYDIR (transient key scratch)
  /root/sslcerts/private -> /var/opt/certinel/private; CERTLIST_RHEL -> /var/opt/certinel/certlist-
  rhel. Updates CSR_HELPER_PATH (app default + env example), the helper 00-common.sh paths,
  deploy.sh manifest + dir creation + bin_t label + fapolicyd trust for the helper, the installer
  dirs/sudoers, and the uninstall/backup tools. Sandbox stays ProtectHome=false until the live
  relocation is verified (4c flips it). Nothing under /root once migrated.

## Fixes & improvements

- **verify:** helper manifest paths -> /opt/certinel/helper (match deploy.sh) (`f5600be`)

## Other changes

- **runbook:** correct the ProtectHome note to true (`27a7b21`)
