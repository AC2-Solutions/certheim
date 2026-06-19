# CSR Dashboard v2.25.0

_Released 2026-06-19. 2 changes since v2.24.0._

## Features

- key-handling Phase 4a - migrate legacy on-disk keys to the vault (`7c7fed3`)
  keystore.migrate_host_keys() sweeps jobs with a host key + no vault path: read via helper, write
  to OpenBao, shred host, record key_vault_path. Admin endpoint POST /api/admin/keys/migrate-to-
  vault + a button in the key-storage settings. Lets /root/sslcerts/private drain so it can be
  retired (Phase 4b). Test + route registration - 85 pass.
- key-handling Phase 3 - per-template key_storage override + short-lived auto-policy (`3661241`)
  cert_templates.key_storage (NULL = inherit global). keystore.effective_mode resolves: template
  override > short-lived auto-rule (key_return_once_max_ttl: templates capped at <= N seconds use
  return_once) > global policy. Passed into secure_after_generate at both generate sites. Admin UI:
  per-template key-storage dropdown + a global short-lived-ttl field. Tests for the precedence - 84
  pass.
