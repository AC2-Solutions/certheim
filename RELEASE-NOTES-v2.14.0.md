# CSR Dashboard v2.14.0

_Released 2026-06-19. 1 change since v2.13.0._

## Features

- in-app user guide for dashboard + admin pages (`93a5a1b`)
  Add a built-in, context-aware help manual so users learn the tool inside the app instead of going
  elsewhere.
  - frontend/app.5-guide.js: a self-contained paginated guide controller driven entirely by a
    data-* contract (data-guide / data-page / data-title / data-group / data-guide-
    toc|prev|next|pglabel) — no per-page JS.
  - index.html: a "Guide" header button + a guide overlay with 21 pages (intro, 6 dashboard areas,
    14 admin areas). The header button is context-aware: it opens to the page matching whatever
    panel you're on. TOC, Prev/Next, ←/→ keys, Esc to close.
  - app.css: theme-aware guide styling (TOC sidebar + scrollable content), responsive stacking on
    narrow screens.
  - deploy.sh / verify.sh: manifest entries for the new asset.
