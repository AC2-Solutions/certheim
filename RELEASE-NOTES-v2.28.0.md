# CSR Dashboard v2.28.0

_Released 2026-06-19. 1 change since v2.27.0._

## Features

- **fips:** report 140-2 vs 140-3 per host (RHEL 8 OpenSSL 1.x aware) (`f564999`)
  fips_status() now distinguishes the standard: OpenSSL 3.x FIPS provider active -> 140-3 (RHEL
  9/10); kernel FIPS + OpenSSL major<3 -> 140-2 (RHEL 8, which has no provider model) so a RHEL 8
  host no longer false-negatives. Adds openssl_major + standard to the status; UI shows 'FIPS 140-x
  validated module active'. docs/fips-compliance.md gains the RHEL 8/9/10 matrix + the single-
  codebase (no per-RHEL branch) guidance. Tests simulate all three hosts.
