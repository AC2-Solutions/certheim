# CSR Dashboard v2.15.0

_Released 2026-06-19. 1 change since v2.14.0._

## Features

- per-panel "?" help buttons that deep-link the guide (`18c2515`)
  Inject a small "?" next to each dashboard/admin panel title; clicking it opens the in-app guide
  directly to that page (via window.openGuide). Done by app.5-guide.js so it stays in sync with the
  guide pages and never collides with a card-header's right-side controls. No new files.
