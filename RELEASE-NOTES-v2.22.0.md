# CSR Dashboard v2.22.0

_Released 2026-06-19. 1 change since v2.21.0._

## Features

- P3 cert-delivery — webhook + cyberark providers, retry backoff + alerts (`57e5b0a`)
  webhook: POST the bundle as JSON to an https receiver; optional HMAC-SHA256 signature header +
  mTLS client cert, both from Vault secret/csr-delivery- webhook/<host> (works unsigned too).
  cyberark: write cert (+key per key_mode) into CyberArk Conjur variables — authenticate then set-
  secret; API key env-only.
  Retry polish: per-job exponential backoff (jobs.delivery_next_attempt, 2min→1h cap) up to
  delivery_max_attempts (default 8), then status 'abandoned' + a job.delivery_failed event;
  job.delivered on success. Both events added to WEBHOOK_EVENTS. _https gains mTLS client-cert
  support.
  Adds delivery.webhook + delivery.cyberark capabilities, admin dropdown options with target hints,
  smoke tests (webhook HMAC shaping, cyberark Conjur shaping, backoff schedule + abandon/alert) — 79
  pass; runbook §5c/§5d.
