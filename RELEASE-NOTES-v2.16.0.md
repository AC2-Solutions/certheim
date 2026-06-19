# CSR Dashboard v2.16.0

_Released 2026-06-19. 1 change since v2.15.0._

## Features

- choose certificate validity at signing (short-lived certs) (`82cc695`)
  Add an issuance-time validity control to Approve & sign so operators can issue short-lived
  certificates (e.g. 30-minute client certs) without editing the template.
  - routes_signing: POST /jobs/<id>/sign accepts an optional `ttl` (seconds), clamped to the
    template/global cap and never below a 30-minute floor; honored by TTL-capable backends
    (OpenBao). New GET /jobs/<id>/sign-options returns {supports_ttl, ttl_min, ttl_max,
    ttl_default} for the UI. Chosen TTL is audit-logged + returned.
  - frontend: a sign modal with a unit selector + slider + synced manual entry and a live expiry
    preview, bounded by the job's template cap. Backends that don't take a TTL keep the simple
    confirm flow.
  - tests: _ttl_bounds clamping (floor/cap/default) + sign-options 404.
