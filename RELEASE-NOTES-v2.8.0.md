# CSR Dashboard v2.8.0

_Released 2026-06-19. 4 changes since v2.7.0._

## Features

- **licensing:** draw the Community/Commercial line - automation is Commercial (`0b0d1fe`)
  Community (free) = manual workflow only (generate CSRs, upload a manually-issued cert,
  fleet/audit). Commercial unlocks ALL automation - every in-UI signing backend, the ACME server,
  automated renewal, and connected integrations (chat/Slack-interactive/email-APIs). Government =
  Commercial + public-sector pack.
  Each capability was already enforced at its call site, so they're gated by listing them in
  COMMERCIAL_CAPABILITIES; added lifecycle.auto_renew + gate. CSR_ENTITLEMENTS=* unlocks licensed
  caps without a license file (dev/eval/self-host).
- **licensing:** community / commercial / government edition tiers (`75f925c`)
  License carries an edition; the app expands it to capabilities (tiers stack: government =
  commercial + public-sector pack). Unlicensed = free Community. Issuer tool takes --edition
  {community,commercial,government}; admin License page shows the edition + effective entitlements.
  COMMERCIAL_CAPABILITIES is empty for now (commercial == community until the line is drawn).
- **licensing:** offline signed-license entitlements + gate government pack (`c5d5411`)

## Other changes

- sterilize environment-specific references for a generic/product repo (`8803405`)
