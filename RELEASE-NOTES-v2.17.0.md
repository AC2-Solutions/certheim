# CSR Dashboard v2.17.0

_Released 2026-06-19. 2 changes since v2.16.0._

## Features

- certificate delivery foundation + OpenBao(vault) provider (P1-A) (`f16b0f2`)
  Ship issued certs to their destinations automatically — the follow-on to short-lived certs
  (docs/cert-delivery-design.md).
  - deliver.py: provider seam (mirrors sign.py/notify.py). deliver_one runs best-effort inline
    from _attach_signed_cert on issue; run_deliveries is the csr-deliver timer's retry pass.
    `openbao` provider writes the bundle to Vault KV v2. Bundle = certificate (always) + private
    key when key_mode ships it and the job has a server-side key (Generate jobs, via helper get-
    key). Capability-gated (delivery.openbao, Commercial).
  - schema: cert_templates.{delivery_backend,key_mode,delivery_target, delivery_reload};
    jobs.{delivery_status,delivery_detail,delivered_at, delivery_attempts} (additive).
  - _attach_signed_cert hook: mark pending + immediate best-effort ship, isolated so delivery
    never fails an issue.
  - csr-deliver systemd service+timer (every 2 min) retries pending/failed; run_deliveries re-
    exported from app.py; deploy.sh/verify.sh wired.
  - admin Template editor: per-template delivery backend + key_mode + target.
  - capabilities: delivery.openbao (Commercial). tests: bundle/gating + config.
  P1-B (next): the ssh host-push provider (per-destination creds from Vault).

## Other changes

- certificate delivery design (shipping issued certs to destinations) (`fc468ca`)
