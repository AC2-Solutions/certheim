# CSR Dashboard v2.19.0

_Released 2026-06-19. 1 change since v2.18.1._

## Features

- per-section hash routing so a refresh restores the current section (`f519e07`)
  Previously only the view (#admin vs dashboard) was in the URL; the active panel wasn't, so a
  refresh dropped you on the default panel. Now each section has its own hash route: #admin/<panel>
  (Overview, Authentication, CSR Subject, …) and #<panel> (Jobs, Fleet, …) for the dashboard. Nav
  clicks set the hash; applyRoute() does the switching and validates the panel, so a refresh (or a
  shared link) lands on the same section. Admin data still (re)loads only when entering the admin
  view, not on every panel switch.
