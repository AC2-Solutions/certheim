# CSR Dashboard v2.13.0

_Released 2026-06-19. 1 change since v2.12.0._

## Features

- support multiple trusted email domains for registration (`a49e3c4`)
  Self-registration could only be filtered to a single email domain. Orgs often have several (e.g.
  ac2solutions.com + mail.mil), so allow a list.
  - app.parse_trusted_domains(): normalizes the stored setting into a list (comma/space/semicolon
    separated, lowercased, '@' stripped, deduped). Stored back-compat in the single
    `trusted_email_domain` key, comma-joined — an existing single-domain value keeps working
    unchanged.
  - register: accept an email whose domain is in ANY configured domain; the rejection message
    lists all allowed domains.
  - /api/auth/info + /api/admin/auth-settings: expose `trusted_email_domains` (list) alongside the
    back-compat `trusted_email_domain` string.
  - admin auth-settings PUT: accept a list OR a multi-domain string; validate each against
    DOMAIN_RE; store comma-joined.
  - csr-set-auth --domain: accept comma/space-separated domains.
  - Admin UI: field relabeled "Trusted email domain(s)", populated from the list, with comma-
    separated help text.
  - Smoke test: multi-domain admin config + registration allow/deny, with state snapshot/restore
    (session-scoped client).
