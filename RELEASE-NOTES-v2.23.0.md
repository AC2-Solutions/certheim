# CSR Dashboard v2.23.0

_Released 2026-06-19. 9 changes since v2.22.0._

## Features

- **ui:** admin dropdown to select private-key storage policy (`1691b9e`)
  Phase 1 of the key-handling design: a key_storage setting (vault | return_once | host, default
  vault) on the signing-config endpoint + a dropdown in Admin → Signing/CA so it can be
  configured/reconfigured on the fly. Persists + validates the enum; enforcement in the generate
  flow is the next phase (UI says so).

## Fixes & improvements

- **deploy:** don't auto-retire csr-slack-listener (opt-in, not deploy-managed) (`9f3b3b0`)
- **deploy:** register both /opt/certinel and /var/opt/certinel fcontext rules (`fe5bd2b`)
  Handles hosts with and without the SELinux /var/opt=/opt equivalency so the data root always
  relabels to var_lib_t.
- **deploy:** register SELinux fcontext against /opt/certinel (var/opt=/opt equivalency) (`344f84e`)
- keep ProtectHome=false — sudo'd helper + keys live under /root (`367dc3e`)
  ProtectHome=true masks /root, which would break the helper exec + key access (helper at
  /root/sslcerts). The /home decoupling is achieved by moving the data to /var/opt/certinel; the
  unit hardening can't go further until the helper/keys also leave /root.
- move data dirs off service-account home to /var/opt/certinel (`326a003`)
  The issued-cert + CSR dirs lived under /home/ansible (an orphaned service account home, SELinux
  user_home_t). Relocate to the FHS add-on-app data root /var/opt/certinel: /home/ansible/issued
  -> /var/opt/certinel/issued /home/ansible/new_request -> /var/opt/certinel/requests
  - app.py CSR_ISSUED_DIR default + env example
  - helper csr_dashboard_helper.d/00-common.sh ISSUED_DIR + CSRDIR
  - csr-api.service: ReadWritePaths -> /var/opt/certinel, and ProtectHome=true now that no /home
    path is used (hardening)
  - deploy.sh creates the dirs with var_lib_t so the confined service can write (matches the DB
    dir); runbook updated
  Private keys (/root/sslcerts/private) and the DB (/var/lib/csr-dashboard) are unchanged. Live
  boxes need the data moved + env/helper updated (migration).

## Other changes

- rename systemd services + timers csr-* -> certinel-* (`068e562`)
- private-key handling design — vault-first, zero at rest, admin-configurable (`0c6744f`)
- CSR Dashboard -> Certinel across UI, emails, chat, docs (`bf78d4c`)
