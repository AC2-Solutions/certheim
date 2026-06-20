# Changelog

All notable changes to the CSR Dashboard. Versions track the `VERSION` file
(the app reports it at `/api/health` and on the admin Overview tile).

## 2.28.1 — 2026-06-20

_Released 2026-06-20. 1 change since v2.28.0._

### Fixes & improvements

- **ci:** make auto-release resilient to concurrent-merge push races (`d2b8027`)
  Rapid back-to-back MR merges each run a `release` job on main. They raced on the push to the
  protected default branch: the loser got a non-fast-forward rejection and failed the pipeline
  (pipelines 1267-1269). Wrap compute/commit/ tag/push in a 5-attempt loop that re-syncs to
  origin/main and recomputes the version each round. The loser now sees the winner's release
  commit+tag, so release.sh returns "none" and the job no-ops cleanly instead of failing.
  No code or release content changes; tag history is unaffected (later releases through v2.28.0
  already landed).

## 2.28.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.27.0._

### Features

- **fips:** report 140-2 vs 140-3 per host (RHEL 8 OpenSSL 1.x aware) (`f564999`)
  fips_status() now distinguishes the standard: OpenSSL 3.x FIPS provider active -> 140-3 (RHEL
  9/10); kernel FIPS + OpenSSL major<3 -> 140-2 (RHEL 8, which has no provider model) so a RHEL 8
  host no longer false-negatives. Adds openssl_major + standard to the status; UI shows 'FIPS 140-x
  validated module active'. docs/fips-compliance.md gains the RHEL 8/9/10 matrix + the single-
  codebase (no per-RHEL branch) guidance. Tests simulate all three hosts.

## 2.27.0 — 2026-06-19

_Released 2026-06-19. 2 changes since v2.26.0._

### Features

- FIPS 140-3 self-check, status visibility + require-FIPS policy (`09a755f`)
  Certinel bundles no crypto (stdlib + system openssl only), so it runs on the platform FIPS-
  validated module in FIPS mode. Add capabilities.fips_status() (kernel /proc flag + the active
  OpenSSL FIPS provider name/version = real validated-module check), expose it via
  /api/admin/capabilities + signing-config, a 'Require FIPS' admin toggle that flags drift, and a
  FIPS status line in Admin -> Signing/CA. New docs/fips-compliance.md states the precise claim +
  boundary (the CA backend carries its own validation). Test + 86 pass.

### Fixes & improvements

- **fips:** parse openssl list -providers indent-agnostically (provider name has no colon) (`a1b129e`)

## 2.26.0 — 2026-06-19

_Released 2026-06-19. 4 changes since v2.25.0._

### Features

- key-handling Phase 4c - ProtectHome=true (helper + keys off /root) (`6853512`)
  The sandbox now masks /home + /root from certinel-api and its children. Safe because the helper
  lives under /opt/certinel and keys go to the vault (only a brief /var/opt/certinel scratch).
  Runbook updated to the relocated paths.
- key-handling Phase 4b - relocate helper + key scratch off /root (`1c0f9f6`)
  Helper /root/sslcerts/scripts -> /opt/certinel/helper; KEYDIR (transient key scratch)
  /root/sslcerts/private -> /var/opt/certinel/private; CERTLIST_RHEL -> /var/opt/certinel/certlist-
  rhel. Updates CSR_HELPER_PATH (app default + env example), the helper 00-common.sh paths,
  deploy.sh manifest + dir creation + bin_t label + fapolicyd trust for the helper, the installer
  dirs/sudoers, and the uninstall/backup tools. Sandbox stays ProtectHome=false until the live
  relocation is verified (4c flips it). Nothing under /root once migrated.

### Fixes & improvements

- **verify:** helper manifest paths -> /opt/certinel/helper (match deploy.sh) (`f5600be`)

### Other changes

- **runbook:** correct the ProtectHome note to true (`27a7b21`)

## 2.25.0 — 2026-06-19

_Released 2026-06-19. 2 changes since v2.24.0._

### Features

- key-handling Phase 4a - migrate legacy on-disk keys to the vault (`7c7fed3`)
  keystore.migrate_host_keys() sweeps jobs with a host key + no vault path: read via helper, write
  to OpenBao, shred host, record key_vault_path. Admin endpoint POST /api/admin/keys/migrate-to-
  vault + a button in the key-storage settings. Lets /root/sslcerts/private drain so it can be
  retired (Phase 4b). Test + route registration - 85 pass.
- key-handling Phase 3 - per-template key_storage override + short-lived auto-policy (`3661241`)
  cert_templates.key_storage (NULL = inherit global). keystore.effective_mode resolves: template
  override > short-lived auto-rule (key_return_once_max_ttl: templates capped at <= N seconds use
  return_once) > global policy. Passed into secure_after_generate at both generate sites. Admin UI:
  per-template key-storage dropdown + a global short-lived-ttl field. Tests for the precedence - 84
  pass.

## 2.24.0 — 2026-06-19

_Released 2026-06-19. 2 changes since v2.23.0._

### Features

- key-handling Phase 2 - vault-first key storage enforcement (`d727e66`)
  keystore.py applies the admin key_storage policy to server-generated keys: vault (default) - write
  the key to OpenBao (secret/certinel-keys/<job>) right after generation and shred the host copy;
  nothing at rest on the host. return_once - same, but the vault copy is destroyed on first fetch.
  host - legacy on-disk keystore. Fails safe: any vault error (or no OpenBao configured) leaves the
  key on the host. Retrieval is unified (fetch_for_job/by_name) across delivery + download.
  Hooked into both generate sites; the 3 key-fetch sites route through keystore; jobs gains
  key_vault_path + key_storage. Smoke tests (store+shred, return_once destroy-on-read, host
  fallback) - 83 pass. Needs the certinel-keys OpenBao policy (ansible) which is already applied
  live.

### Fixes & improvements

- **keystore:** _read returns None on 404 (missing/destroyed key), not raise (`fb6ccae`)

## 2.23.0 — 2026-06-19

_Released 2026-06-19. 9 changes since v2.22.0._

### Features

- **ui:** admin dropdown to select private-key storage policy (`1691b9e`)
  Phase 1 of the key-handling design: a key_storage setting (vault | return_once | host, default
  vault) on the signing-config endpoint + a dropdown in Admin → Signing/CA so it can be
  configured/reconfigured on the fly. Persists + validates the enum; enforcement in the generate
  flow is the next phase (UI says so).

### Fixes & improvements

- **deploy:** don't auto-retire csr-slack-listener (opt-in, not deploy-managed) (`9f3b3b0`)
- **deploy:** register both /opt/certinel and /var/opt/certinel fcontext rules (`fe5bd2b`)
  Handles hosts with and without the SELinux /var/opt=/opt equivalency so the data root always
  relabels to var_lib_t.
- **deploy:** register SELinux fcontext against /opt/certinel (var/opt=/opt equivalency) (`344f84e`)
- keep ProtectHome=false — sudo'd helper + keys live under /root (`367dc3e`)
  ProtectHome=true masks /root, which would break the helper exec + key access (helper at
  /root/sslcerts). The /home decoupling is achieved by moving the data to /var/opt/certinel; the
  unit hardening can't go further until the helper/keys also leave /root.
- move data dirs off service-account home to /var/opt/certinel (`326a003`)
  The issued-cert + CSR dirs lived under /home/ansible (an orphaned service account home, SELinux
  user_home_t). Relocate to the FHS add-on-app data root /var/opt/certinel: /home/ansible/issued
  -> /var/opt/certinel/issued /home/ansible/new_request -> /var/opt/certinel/requests
  - app.py CSR_ISSUED_DIR default + env example
  - helper csr_dashboard_helper.d/00-common.sh ISSUED_DIR + CSRDIR
  - csr-api.service: ReadWritePaths -> /var/opt/certinel, and ProtectHome=true now that no /home
    path is used (hardening)
  - deploy.sh creates the dirs with var_lib_t so the confined service can write (matches the DB
    dir); runbook updated
  Private keys (/root/sslcerts/private) and the DB (/var/lib/csr-dashboard) are unchanged. Live
  boxes need the data moved + env/helper updated (migration).

### Other changes

- rename systemd services + timers csr-* -> certinel-* (`068e562`)
- private-key handling design — vault-first, zero at rest, admin-configurable (`0c6744f`)
- CSR Dashboard -> Certinel across UI, emails, chat, docs (`bf78d4c`)

## 2.22.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.21.0._

### Features

- P3 cert-delivery — webhook + cyberark providers, retry backoff + alerts (`57e5b0a`)
  webhook: POST the bundle as JSON to an https receiver; optional HMAC-SHA256 signature header +
  mTLS client cert, both from Vault secret/csr-delivery- webhook/<host> (works unsigned too).
  cyberark: write cert (+key per key_mode) into CyberArk Conjur variables — authenticate then set-
  secret; API key env-only.
  Retry polish: per-job exponential backoff (jobs.delivery_next_attempt, 2min→1h cap) up to
  delivery_max_attempts (default 8), then status 'abandoned' + a job.delivery_failed event;
  job.delivered on success. Both events added to WEBHOOK_EVENTS. _https gains mTLS client-cert
  support.
  Adds delivery.webhook + delivery.cyberark capabilities, admin dropdown options with target hints,
  smoke tests (webhook HMAC shaping, cyberark Conjur shaping, backoff schedule + abandon/alert) — 79
  pass; runbook §5c/§5d.

## 2.21.0 — 2026-06-19

_Released 2026-06-19. 2 changes since v2.20.1._

### Features

- P2 cert-delivery providers — pull (token-bundle) + k8s (TLS Secret) (`761a05c`)
  pull: dashboard stores the issued bundle behind a scoped, single-use, short-lived token; the
  destination fetches it at GET /deliver/pull/<token> (JSON / pem / cert). No push path, no Vault
  grant — works through a one-way firewall toward the dashboard. New delivery_pulls table;
  routes_deliver.py public blueprint; certinel-deliver timer purges expired tokens.
  k8s: server-side-apply a kubernetes.io/tls Secret into <ns>/<secret> (cred from Vault secret/csr-
  delivery-k8s/<cluster>); requires key_mode=ship.
  Adds delivery.pull + delivery.k8s capabilities, admin dropdown options with per-backend target
  hints, smoke tests (pull lifecycle/formats, k8s guards, k8s env-gating), runbook sections, and the
  k8s cred path to the policy doc.

### Fixes & improvements

- serve pull endpoint under /api/ so it rides the existing nginx proxy (`708b5d3`)
  Only /csr/api/ is proxied to Flask; /deliver/* fell through to the SPA. Move the route to
  /api/deliver/pull/<token> (no per-deployment nginx change).

## 2.20.1 — 2026-06-19

_Released 2026-06-19. 1 change since v2.20.0._

### Fixes & improvements

- hide Administration guide pages from non-admin users (`de543a5`)
  The in-app guide showed all 21 pages to everyone, including the 14 admin pages. Filter the
  Administration group to admins only - regular users see just Getting started + the Dashboard
  guides (they can't reach the admin screens anyway). Recomputed on each open so it tracks the
  logged-in user.

## 2.20.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.19.1._

### Features

- admins can create users from the Users panel (`cd9d18f`)
  POST /api/admin/users is now mode-aware: in LOCAL mode it takes first/last + email + an initial
  password (admin-supplied or auto-generated, policy-checked) and creates a login-ready account with
  an auto-derived first.last username; in mTLS mode it keeps the CAC-DN pre-create. A "+ Create
  user" button + modal in Admin → Users drives it, showing the generated temp password once. Smoke:
  mtls create + duplicate 409 + temp-password policy compliance.

## 2.19.1 — 2026-06-19

_Released 2026-06-19. 1 change since v2.19.0._

### Fixes & improvements

- CSR-subject OOBE no longer hijacks the section on every refresh (`920f055`)
  loadCsrSubject() (run on every admin entry/refresh) auto-clicked the CSR Subject tab whenever the
  org subject was unmarked-configured, using a per-page-load flag - so on a box where the subject
  was never saved, every refresh yanked the admin to CSR Subject, overriding the section route. Drop
  the auto-navigation entirely (it only ever ran inside the admin view, so it could only hijack);
  keep the setup banner as the nudge. Combined with the new per-section hash routing, a refresh now
  stays on the current section.

## 2.19.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.18.1._

### Features

- per-section hash routing so a refresh restores the current section (`f519e07`)
  Previously only the view (#admin vs dashboard) was in the URL; the active panel wasn't, so a
  refresh dropped you on the default panel. Now each section has its own hash route: #admin/<panel>
  (Overview, Authentication, CSR Subject, …) and #<panel> (Jobs, Fleet, …) for the dashboard. Nav
  clicks set the hash; applyRoute() does the switching and validates the panel, so a refresh (or a
  shared link) lands on the same section. Admin data still (re)loads only when entering the admin
  view, not on every panel switch.

## 2.18.1 — 2026-06-19

_Released 2026-06-19. 1 change since v2.18.0._

### Fixes & improvements

- **csr-subject:** duplicate OUs (e.g. doubled DoD) in the admin subject editor (`ac454eb`)
  The OU chip put data-ou on BOTH the chip <span> and its delete <a>, so _csrSubjectCfg()'s `[data-
  ou]` selector read every OU twice. Applying a profile (e.g. DoD) then adding any OU re-read the
  doubled list and re-rendered, showing OU=DoD twice in the chips + preview (and sending duplicates
  on save; the backend clean_config deduped, so issued CSRs were unaffected, but the UI was wrong
  and confusing). Scope the selector to span[data-ou].

## 2.18.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.17.0._

### Features

- SSH host-push delivery provider + deployment runbook (P1-B) (`f0c25d3`)
  - deliver.py: `ssh` provider — scp the cert (+key per key_mode) to the destination host and run
    an optional reload, authenticating with a per-destination SSH credential fetched from Vault
    (secret/csr-delivery-ssh/<host>: username/private_key/port). Host is regex-validated; the temp
    key file is 0600 and removed after.
  - capabilities: delivery.ssh (Commercial).
  - admin Template editor: "Deliver → SSH host" option + an ssh-only reload command field.
  - docs/cert-delivery-deployment.md: turnkey per-client runbook — the OpenBao `csr-delivery`
    policy (cert-write + ssh-cred-read, no delete) + AppRole attach (CLI + the K8s recovery-root
    flow), SSH destination setup, and the per-template config.
  - tests: ssh provider registered + ssh/reload config round-trip.

## 2.17.0 — 2026-06-19

_Released 2026-06-19. 2 changes since v2.16.0._

### Features

- certificate delivery foundation + OpenBao(vault) provider (P1-A) (`f16b0f2`)
  Ship issued certs to their destinations automatically — the follow-on to short-lived certs
  (docs/cert-delivery-design.md).
  - deliver.py: provider seam (mirrors sign.py/notify.py). deliver_one runs best-effort inline
    from _attach_signed_cert on issue; run_deliveries is the certinel-deliver timer's retry pass.
    `openbao` provider writes the bundle to Vault KV v2. Bundle = certificate (always) + private
    key when key_mode ships it and the job has a server-side key (Generate jobs, via helper get-
    key). Capability-gated (delivery.openbao, Commercial).
  - schema: cert_templates.{delivery_backend,key_mode,delivery_target, delivery_reload};
    jobs.{delivery_status,delivery_detail,delivered_at, delivery_attempts} (additive).
  - _attach_signed_cert hook: mark pending + immediate best-effort ship, isolated so delivery
    never fails an issue.
  - certinel-deliver systemd service+timer (every 2 min) retries pending/failed; run_deliveries re-
    exported from app.py; deploy.sh/verify.sh wired.
  - admin Template editor: per-template delivery backend + key_mode + target.
  - capabilities: delivery.openbao (Commercial). tests: bundle/gating + config.
  P1-B (next): the ssh host-push provider (per-destination creds from Vault).

### Other changes

- certificate delivery design (shipping issued certs to destinations) (`fc468ca`)

## 2.16.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.15.0._

### Features

- choose certificate validity at signing (short-lived certs) (`82cc695`)
  Add an issuance-time validity control to Approve & sign so operators can issue short-lived
  certificates (e.g. 30-minute client certs) without editing the template.
  - routes_signing: POST /jobs/<id>/sign accepts an optional `ttl` (seconds), clamped to the
    template/global cap and never below a 30-minute floor; honored by TTL-capable backends
    (OpenBao). New GET /jobs/<id>/sign-options returns {supports_ttl, ttl_min, ttl_max,
    ttl_default} for the UI. Chosen TTL is audit-logged + returned.
  - frontend: a sign modal with a unit selector + slider + synced manual entry and a live expiry
    preview, bounded by the job's template cap. Backends that don't take a TTL keep the simple
    confirm flow.
  - tests: _ttl_bounds clamping (floor/cap/default) + sign-options 404.

## 2.15.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.14.0._

### Features

- per-panel "?" help buttons that deep-link the guide (`18c2515`)
  Inject a small "?" next to each dashboard/admin panel title; clicking it opens the in-app guide
  directly to that page (via window.openGuide). Done by app.5-guide.js so it stays in sync with the
  guide pages and never collides with a card-header's right-side controls. No new files.

## 2.14.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.13.0._

### Features

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

## 2.13.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.12.0._

### Features

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

## 2.12.0 — 2026-06-19

_Released 2026-06-19. 2 changes since v2.11.0._

### Features

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

### Other changes

- sterilize remaining homelab references for a generic repo (`5ae7361`)

## 2.11.0 — 2026-06-19

_Released 2026-06-19. 2 changes since v2.10.0._

### Features

- **acme:** ACME server 4b - DNS-01 validation, revoke-cert, key rollover (`019a222`)

### Other changes

- **acme:** note 4b (DNS-01 / revoke / key rollover) is implemented (`3766dd4`)

## 2.10.0 — 2026-06-19

_Released 2026-06-19. 2 changes since v2.9.0._

### Features

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

### Other changes

- Revert "Merge branch 'feat/community-scale-cap' into 'main'" (`af95d17`)

## 2.9.0 — 2026-06-19

_Released 2026-06-19. 1 change since v2.8.0._

### Features

- **licensing:** redraw to full-product-capped-by-scale Community tier (`a938da7`)
  Community (free) = the full single-instance product capped at N active certs (default 25, admin-
  tunable via community_cert_limit). The core loop is free: in-UI signing via OpenBao/standalone
  Windows CA/ACME client, automated renewal, fleet, audit, SMTP, local/CAC auth. Commercial removes
  the cap (scale.unlimited_certs) + adds enterprise breadth (CyberArk/EJBCA/Venafi/AWS PCA, ACME
  server, chat/email integrations). Government = + public-sector pack.
  Cap enforced once, in _attach_signed_cert (covers approve&sign + manual upload + auto-renew);
  renewals (renewed_from) are exempt. Usage surfaced on Admin->License.

## 2.8.0 — 2026-06-19

_Released 2026-06-19. 4 changes since v2.7.0._

### Features

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

### Other changes

- sterilize environment-specific references for a generic/product repo (`8803405`)

## 2.7.0 — 2026-06-18

_Released 2026-06-18. 2 changes since v2.6.0._

### Features

- **signing:** ACME server endpoint - dashboard as an RFC 8555 CA [phase 4] (`a18beab`)

### Other changes

- **acme:** document the ACME server + reverse-proxy requirement (`46d16f2`)

## 2.6.0 — 2026-06-18

_Released 2026-06-18. 1 change since v2.5.0._

### Features

- **signing:** enterprise CA providers - EJBCA, Venafi, AWS PCA, Enterprise AD CS [phase 3] (`4882549`)

## 2.5.0 — 2026-06-18

_Released 2026-06-18. 2 changes since v2.4.0._

### Features

- **release:** generate detailed notes from commit bodies (`51b9b96`)
  The auto-generated CHANGELOG/release notes were one terse line per commit (subject only). Rework
  tools/release.sh to include each commit's body - re-flowed into wrapped, indented paragraphs with
  in-body bullet lists preserved as nested items - grouped into Breaking changes / Features / Fixes
  & improvements / Other, each entry tagged with its short hash, plus a "N changes since vPREV"
  summary line. So every release now reads as real, detailed notes instead of a subject list.

### Fixes & improvements

- **ci:** create the GitLab Release object reliably (api scope + browser UA) (`b1ca16f`)
  The auto-release job pushed tags fine but the GitLab Release *object* step silently warned off for
  v2.3.0/v2.4.0. Two causes:
  - RELEASE_TOKEN had the write_repository scope, which is Git-over-HTTP only and cannot call the
    API, so POST /releases 403'd. Token reissued with the api scope (variable updated out of
    band).
  - The curl had no browser User-Agent, which Cloudflare bot-blocks (1010) on API writes to the
    public host.
  Add -A "Mozilla/5.0" and surface the HTTP status so a future failure isn't silent. Docs updated to
  require the api scope.

## 2.4.0 — 2026-06-18

### Added / Changed
- (signing) cloud DNS-01 solvers for ACME (Cloudflare/Route53/Azure) [phase 2]

## 2.3.0 — 2026-06-18

### Added / Changed
- (signing) ACME (RFC 8555) client provider [phase 1]

## 2.2.0 — 2026-06-18

### Added / Changed
- (renew) automated certificate renewal loop

### Fixed
- (audit) make log_event safe outside a request context
- (deploy) ship backend/renew.py in the deploy + verify manifests

## 2.1.0 — 2026-06-18

### Added / Changed
- (fleet) auto-track issued certs in fleet monitoring
- (signing) Windows CA (AD CS) provider — sign via certreq over SSH

### Fixed
- (groups) assign a user to multiple groups in one Save (user-edit modal)
- (audit) missing sqlite3/Path imports (500s) + unregistered webhook events

## 2.0.0

In-UI certificate **signing** (the cert is produced by a CA backend, not just
an out-of-band upload), a configurable **organization identity**, and a large
internal restructure. See `RELEASE-NOTES-v2.0.0.md` for the narrative.

### Added
- **In-UI CA signing (OpenBao PKI)** — approval-gated `POST /api/jobs/<id>/sign`:
  a signer/admin approves and the cert is issued via the CA backend, feeding the
  same verify → `issued` → filesystem-drop → webhook → email path as a manual
  upload. New `backend/sign.py` provider seam; the CA key never touches the app
  (scoped AppRole credential, env-only). Admin **Signing / CA** tab + per-job
  **Approve & sign** with cert-chain download.
- **Pluggable signing providers** — provider registry (manual / OpenBao /
  CyberArk slot); admins pick the provider and set its connection in the UI.
  OpenBao fully implemented; CyberArk is a configurable slot pending an instance.
- **Per-template signing policy + auto-sign** — `jobs.template_id`;
  `resolve_signing_policy()` lets a template override the global default
  (backend/role/TTL) or inherit it; `auto_sign` issues on request. Admin
  template editor gains a Signing column.
- **Certificate revocation + CRL/OCSP** — `POST /api/jobs/<id>/revoke`
  (signer/admin), a `revoked` job state, a Revoke button on issued jobs; CRL/OCSP
  distribution points surfaced.
- **Configurable CSR subject / organization identity** — the subject DN
  (`C/ST/L/O/OUs/domain`) is no longer hardcoded; an admin **CSR Subject** tab
  with org-profile presets (DoD + services, Federal Civilian, Commercial),
  add/remove **OU tags**, a live DN preview, and a first-run (OOBE) prompt. The
  helper parses (never sources) an admin-written `subject.conf`.
- **Capability / feature-flag layer** (`backend/capabilities.py`) — features
  resolve as entitled (offline, no phone-home) AND env-supported; the UI shows
  on / off / not-licensed / unavailable-here.
- **Endpoint smoke harness** (`tests/test_smoke.py`) gating every change, run as
  a hard CI stage.

### Changed
- **`app.py` decomposed into Flask blueprints** —
  `routes_{auth,jobs,requests,groups,me,admin,integrations,feedback,signing}.py`
  (app.py 5,248 → ~1,700-line core). Behavior-preserving (url_map identical).
- Multi-method email (SMG/SMTP/Mailgun/SendGrid/none), chat integrations
  (Slack/Teams/Discord/webhook) with rich messages, Slack interactivity
  (HTTP Request URL + Socket Mode), and a configurable login banner.
- Frontend `app.js` split into ordered pieces + extracted `app.css`.

### Schema (additive, auto-migrated)
- `jobs`: `approved_by_dn`, `approved_at`, `signed_via`, `template_id`,
  `revoked_at`, `revoked_by_dn`.
- `cert_templates`: `signer_backend`, `openbao_role`, `max_ttl`, `auto_sign`.

## 1.2.0

### Added
- **Admin user deletion** — `DELETE /api/admin/users` (admin + CSRF). Guards:
  cannot delete yourself, cannot delete the last remaining admin, 404 if
  absent. Removes the user + their group memberships; **retains their jobs**
  (historical). `?purge=1` also detaches owned cert templates (`owner_dn` →
  NULL). UI: a Delete button in the user-edit modal (hidden for your own
  account) that requires typing the user's CN to confirm.
- **First-admin bootstrap** — `CSR_BOOTSTRAP_FIRST_ADMIN=1` makes the first
  user to log in on an empty database an admin; self-disables once any user
  exists. Default off. Only safe under real CAC mTLS. (`_env_bool` helper.)
- **`csr-bootstrap-admin` CLI** — promote a DN to admin directly in the DB
  (no prior login needed); `--list` shows current admins. Installed to
  `/usr/local/sbin`.
- **CA trust portal** — publish root/intermediate CA certs so clients can
  download them to build trust. Public unauthenticated `GET /api/trust` +
  `/api/trust/<name>`; admin upload/delete validates the file is a CA cert
  (`CA:TRUE`) and **rejects private keys**. New admin **Trust** panel.
- **CAC mTLS as an installer option** — `ENABLE_MTLS` (+ `DOD_CA_BUNDLE`).
  The generated nginx server block carries the enforcing lines active (yes)
  or commented with `optional_no_ca` (no). The offline installer auto-publishes
  the DoD bundle to the trust portal when mTLS is enabled.
- **Guided offline installer** — `offline-install.sh` prompts (domain,
  hostname, optional email, mTLS, first-admin, DB restore) with a confirm
  summary; `--unattended` reads `START_HERE`; `--help` works as non-root.
  Email is optional; domain/hostname are templated into the deployed files.
- **UI domain badge** — bare-hostname suffix shown as a highlighted
  `.suffix-badge` with a worked example.

### Changed
- **nginx `30-csr.conf` is now a location fragment** (no `server{}` wrapper),
  included inside a server block — matching the rcdn01 layout. Uses
  `root /var/www` (not `alias`). The installers generate a standalone server
  block (`conf.d/csr-dashboard.conf`) for fresh/air-gapped boxes.
- **`deploy.sh`** verifies the running version against `VERSION` after a
  restart (a failed loopback curl is "couldn't check", not an error), and uses
  `reload-or-restart` for nginx.

### Fixed
- **Orphan-certs 500** — the admin orphan-certs listing read
  `/home/ansible/issued` directly, which 500s when csrapi can't read it on a
  STIG box. Now routed through a root helper subcommand `list-issued`.
- **`certinel-api.service`** — `/etc/csr-dashboard` added to `ReadWritePaths` so
  the admin UI can persist `email.conf` / `integrations.conf` under
  `ProtectSystem=full` (every save previously 500'd "read-only file system").
- **`/home/ansible/issued`** is created csrapi-writable by the installers (the
  cert drop was hitting EACCES).

## 1.1.0

### Added
- **Pluggable email providers** — admin picks one delivery method (dropdown):
  SMG relay (plain SMTP:25), standard **SMTP** (STARTTLS/SSL + auth), or
  **Mailgun** HTTP API (US/EU). Only the selected provider is active; secrets
  are masked and preserved across saves.
- **GitLab issue-driven signing loop** — a new CSR job opens a GitLab issue
  (CSR pasted in, assigned to signers, labeled); a signer pastes/attaches the
  signed cert in the issue and the dashboard attaches it to the job (inbound
  `POST /api/webhooks/gitlab`, validated by `X-Gitlab-Token`). Admin **GitLab**
  panel + test-connection.

## 1.0.1

### Added / Fixed (offline + repo hygiene)
- Restructured the repo from a flat dump into the real tree the scripts expect.
- Added the missing pinned `requirements.txt` and the production
  `nginx/30-csr.conf`.
- Added `install/online-install.sh` (connected/non-STIG installer).
- Documented the STIG offline install failures + fixes (venv `g+rX`, fapolicyd
  exec-by-path, single-line systemd `ExecStart`, firewalld 443, etc.).

## 1.0.0
- Initial CSR Dashboard: Flask/SQLite certificate request + lifecycle
  dashboard for the RHEL fleet, behind nginx with DoD PKI CAC mTLS.
