# CSR Dashboard v2.18.0

_Released 2026-06-19. 1 change since v2.17.0._

## Features

- SSH host-push delivery provider + deployment runbook (P1-B) (`f0c25d3`)
  - deliver.py: `ssh` provider — scp the cert (+key per key_mode) to the destination host and run
    an optional reload, authenticating with a per-destination SSH credential fetched from Vault
    (secret/csr-delivery-ssh/<host>: username/private_key/port). Host is regex-validated; the temp
    key file is 0600 and removed after.
  - capabilities: delivery.ssh (Commercial).
  - admin Template editor: "Deliver → SSH host" option + an ssh-only reload command field.
  - docs/cert-delivery-deployment.md: turnkey per-client runbook — the OpenBao `csr-delivery`
    policy (cert-write + ssh-cred-read, no delete) + AppRole attach (CLI + the K8s recovery-root
    flow), SSH destination setup, and the per-template config.
  - tests: ssh provider registered + ssh/reload config round-trip.
