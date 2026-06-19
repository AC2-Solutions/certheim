# CSR Dashboard v2.24.0

_Released 2026-06-19. 2 changes since v2.23.0._

## Features

- key-handling Phase 2 - vault-first key storage enforcement (`d727e66`)
  keystore.py applies the admin key_storage policy to server-generated keys: vault (default) - write
  the key to OpenBao (secret/certinel-keys/<job>) right after generation and shred the host copy;
  nothing at rest on the host. return_once - same, but the vault copy is destroyed on first fetch.
  host - legacy on-disk keystore. Fails safe: any vault error (or no OpenBao configured) leaves the
  key on the host. Retrieval is unified (fetch_for_job/by_name) across delivery + download.
  Hooked into both generate sites; the 3 key-fetch sites route through keystore; jobs gains
  key_vault_path + key_storage. Smoke tests (store+shred, return_once destroy-on-read, host
  fallback) - 83 pass. Needs the certinel-keys OpenBao policy (ansible) which is already applied
  live.

## Fixes & improvements

- **keystore:** _read returns None on 404 (missing/destroyed key), not raise (`fb6ccae`)
