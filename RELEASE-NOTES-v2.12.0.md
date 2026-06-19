# CSR Dashboard v2.12.0

_Released 2026-06-19. 2 changes since v2.11.0._

## Features

- license-renewal reminder banner near expiry (`fc4f9ea`)
  Surface a renewal reminder in the UI as an installed license nears its expiry date, so an operator
  can renew before licensed features lapse to the Community baseline.
  - licensing.expiry_notice(within_days): a {days_left, expires, edition, customer} warning when a
    *valid* license expires within the window, else None (Community/perpetual/expired -> None).
    Day count is ceil'd so a partial final day still counts.
  - /api/me returns license_notice, with the window keyed to the caller: 60 days for admins (act-
    early), 30 for everyone else.
  - Frontend renders a dismissible warning strip, further confined by the current view: the 60-day
    window shows on the Admin UI, while the main dashboard only warns inside 30 days. Dismiss is
    per browser session.
  - Smoke test for the /api/me notice (present at 20d, absent at 200d).

## Other changes

- sterilize remaining homelab references for a generic repo (`5ae7361`)
