# CSR Dashboard v2.18.1

_Released 2026-06-19. 1 change since v2.18.0._

## Fixes & improvements

- **csr-subject:** duplicate OUs (e.g. doubled DoD) in the admin subject editor (`ac454eb`)
  The OU chip put data-ou on BOTH the chip <span> and its delete <a>, so _csrSubjectCfg()'s `[data-
  ou]` selector read every OU twice. Applying a profile (e.g. DoD) then adding any OU re-read the
  doubled list and re-rendered, showing OU=DoD twice in the chips + preview (and sending duplicates
  on save; the backend clean_config deduped, so issued CSRs were unaffected, but the UI was wrong
  and confusing). Scope the selector to span[data-ou].
