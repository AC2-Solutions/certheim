# CSR Dashboard v2.27.0

_Released 2026-06-19. 2 changes since v2.26.0._

## Features

- FIPS 140-3 self-check, status visibility + require-FIPS policy (`09a755f`)
  Certinel bundles no crypto (stdlib + system openssl only), so it runs on the platform FIPS-
  validated module in FIPS mode. Add capabilities.fips_status() (kernel /proc flag + the active
  OpenSSL FIPS provider name/version = real validated-module check), expose it via
  /api/admin/capabilities + signing-config, a 'Require FIPS' admin toggle that flags drift, and a
  FIPS status line in Admin -> Signing/CA. New docs/fips-compliance.md states the precise claim +
  boundary (the CA backend carries its own validation). Test + 86 pass.

## Fixes & improvements

- **fips:** parse openssl list -providers indent-agnostically (provider name has no colon) (`a1b129e`)
