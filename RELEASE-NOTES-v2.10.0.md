# CSR Dashboard v2.10.0

_Released 2026-06-19. 2 changes since v2.9.0._

## Features

- **licensing:** Community free tier = OpenBao signing (no usage caps) (`9b33391`)
  Redraw the free/paid line on FEATURE BREADTH, not a usage cap. An active-cert cap is trivially
  gamed (delete an issued cert, reissue, repeat), so it's dropped entirely. Instead:
  - Community (free): the core request -> sign -> issue loop via the open-source CA (OpenBao) +
    on-demand renewal through it + manual cert upload + fleet, audit, SMTP, local/CAC auth. No
    counters, nothing to game.
  - Commercial: every OTHER signing backend (Windows/CyberArk/EJBCA/Venafi/AWS PCA, ACME client),
    the ACME server, background automated renewal, and connected integrations (chat / Slack-
    interactive / email APIs).
  - Government: Commercial + the public-sector pack.
  Implementation is one line: ca.signing.openbao leaves COMMERCIAL_CAPABILITIES.

## Other changes

- Revert "Merge branch 'feat/community-scale-cap' into 'main'" (`af95d17`)
