# CSR Dashboard v2.19.1

_Released 2026-06-19. 1 change since v2.19.0._

## Fixes & improvements

- CSR-subject OOBE no longer hijacks the section on every refresh (`920f055`)
  loadCsrSubject() (run on every admin entry/refresh) auto-clicked the CSR Subject tab whenever the
  org subject was unmarked-configured, using a per-page-load flag - so on a box where the subject
  was never saved, every refresh yanked the admin to CSR Subject, overriding the section route. Drop
  the auto-navigation entirely (it only ever ran inside the admin view, so it could only hijack);
  keep the setup banner as the nudge. Combined with the new per-section hash routing, a refresh now
  stays on the current section.
