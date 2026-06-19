# CSR Dashboard v2.20.1

_Released 2026-06-19. 1 change since v2.20.0._

## Fixes & improvements

- hide Administration guide pages from non-admin users (`de543a5`)
  The in-app guide showed all 21 pages to everyone, including the 14 admin pages. Filter the
  Administration group to admins only - regular users see just Getting started + the Dashboard
  guides (they can't reach the admin screens anyway). Recomputed on each open so it tracks the
  logged-in user.
