# Certheim Community edition — changelog

## 6.2.1 — 2026-07-14

_Released 2026-07-14. 2 changes since community-v6.2.0._

### Fixes & improvements

- **diagnostics:** bootstrap-flag check must say the flag is inert (`9cdbfcf`)
  Both bootstrap paths only fire while the users table is EMPTY (the flag is self-disabling), so on
  a populated install the old hint ('the next new identity to sign in becomes an admin') was simply
  false - live validation on a populated install confirmed a new sign-in gets the uniform 401. Now:
  flag set + empty table = ok (expected setup state); flag set + accounts exist = warn as INERT with
  the real residual risk (a reset/lost data store would crown the first identity to appear).

### Other changes

- **guide:** add Database + Trust store guide pages (`7cf8d3c`)

## 6.2.0 — 2026-07-14

_Released 2026-07-14. 1 change since community-v6.1.0._

### Features

- **support:** configuration self-checks in the bundle + on-demand health check (`f69dd37`)
  A diagnostics battery (db writable, disk space, email, auth sanity, license/build mismatch,
  signing-backend reachability, scheduler staleness, stuck requests, delivery failures, helper,
  fleet freshness) embedded in every support bundle as diagnostics.json/.txt and exposed via GET
  /api/admin/diagnostics + a Run health check button, so obvious misconfigurations surface before a
  ticket is opened. Premium surfaces probe via import/table guards; every check is exception-proofed
  and secret-free. The expiry-warn pass now records last_expiry_warn_at so a dead timer/CronJob is
  detectable.

## 6.1.0 — 2026-07-14

_Released 2026-07-14. 1 change since community-v6.0.1._

### Features

- **ui:** sticky header, independent pane scroll, content-pane zoom + image cache-bust (`c830c2f`)
  - header is now position:sticky so it stays visible on scroll
  - sidebar nav pinned below header, scrolls in its own region (--header-h)
  - floating pane-zoom control scales only .panel-body (CSS zoom), persisted
  - Containerfile stamps a content-hash ?v= on assets (K8s path parity with deploy.sh)

## 6.0.1 — 2026-07-10

_Released 2026-07-10. 4 changes since community-v6.0.0._

### Fixes & improvements

- drop certinel->certheim env dual-read shim (Phase 5) (`1bf0a10`)
  Remove the Phase-1 backwards-compat shim now that every install's env file, the container image's
  baked env, and the entrypoint all use the canonical CERTHEIM_* spelling:
  - backend/envcompat.py: candidates()/getenv() read only the exact name (no CSR_/CERTINEL_
    fallback). Thin API kept so call sites are unchanged.
  - backend/app.py _load_env_file: drop the legacy twin-bridge loop.
  - tests/test_envcompat.py: rewritten to assert canonical-only (no fallback).
  Portal /api/v1/certinel/* routes and the container/deploy migration tooling (intentional legacy
  old-refs) are unaffected. refactor: => PATCH release.

### Other changes

- **rename:** bake canonical CERTHEIM_* env in container image (Phase 5) (`171c615`)
- **keystore:** update smoke assertions to certheim/_shared/keys path (`d8ed0a2`)
- **keystore:** move vault key path certinel-keys -> certheim/_shared/keys (`3b0c446`)

## 6.0.0 — 2026-07-09

_Released 2026-07-09. 1 change since community-v5.1.0._

### Breaking changes

- **rename-p2:** rename internal certinel identifiers to certheim + migration hook (`4fd11deb`)
  Phase 2 of the internal rename (docs/certheim-rename-design.md). Renames every load-bearing
  certinel identifier the repo owns, and ships an in-place migration so existing installs upgrade
  without data loss.
  Renamed:
  - paths: /opt|/etc|/var/lib|/var/opt/certinel -> /certheim; /etc/pki/certinel,
    /etc/nginx/certinel.d, conf.d/certinel.conf, sudoers
  - systemd: certinel-api + all timers -> certheim-* (git mv, 12 units)
  - tools: certinel-{backup,restore,db-migrate,bootstrap-admin,uninstall,set-auth, doctor,doctor-
    alert,issue-license} -> certheim-* (git mv)
  - helper: certinel_helper.sh + .d/ -> certheim_helper.sh (git mv)
  - service account default certinel -> certheim; config/certinel.env.example ->
    certheim.env.example; env keys CSR_*/CERTINEL_* -> CERTHEIM_* (read via the Phase-1 envcompat
    shim, so old env files keep working)
  - deploy.sh MANIFEST + verify.sh manifest + Containerfile + entrypoint + helm + frontend guide +
    docs/runbook + .gitlab-ci.yml (pg user, tmp dirs, unit lint, portal upload URLs)
  Migration (move + upgrade hook):
  - tools/certheim-migrate.sh: idempotent backup -> stop -> move dirs -> create certheim account +
    chown-remap -> rewrite env/nginx/sudoers -> SELinux relabel -> fapolicyd re-trust -> daemon-
    reload. Refuses ambiguous (both-layouts) state.
  - deploy.sh runs it automatically when it detects the legacy layout (never on --diff); legacy-
    unit retirement list extended with certinel-*.
  - Containerfile bakes the LEGACY env spellings (values = new paths) so a pod overriding a legacy
    var still wins; entrypoint keeps reading a legacy-mounted volume if present.
  Kept on purpose: /csr/ URL + /var/www/csr web root (semantic 'certificate signing request');
  OpenBao certinel-keys path + the openbao role default (external systems); the /certinel flat
  legacy image tags; CI variable NAMES (CERTINEL_*_SECRET); git history (CHANGELOG). Portal DB
  table/headers/endpoints are Phase 4.
  Gates: py_compile, bash -n (incl. certheim-migrate.sh), 95 pytest passed, RPM builds clean (0
  certinel-named files, renamed units/tools present).
  BREAKING for pre-5.2 installs — auto-migrated by deploy.sh/certheim-setup; rehearsed on disa in
  Phase 3 before the fleet. Propagates to Commercial/Government.

### Features

- **rename-p2:** rename internal certinel identifiers to certheim + migration hook (`4fd11deb`)
  Phase 2 of the internal rename (docs/certheim-rename-design.md). Renames every load-bearing
  certinel identifier the repo owns, and ships an in-place migration so existing installs upgrade
  without data loss.
  Renamed:
  - paths: /opt|/etc|/var/lib|/var/opt/certinel -> /certheim; /etc/pki/certinel,
    /etc/nginx/certinel.d, conf.d/certinel.conf, sudoers
  - systemd: certinel-api + all timers -> certheim-* (git mv, 12 units)
  - tools: certinel-{backup,restore,db-migrate,bootstrap-admin,uninstall,set-auth, doctor,doctor-
    alert,issue-license} -> certheim-* (git mv)
  - helper: certinel_helper.sh + .d/ -> certheim_helper.sh (git mv)
  - service account default certinel -> certheim; config/certinel.env.example ->
    certheim.env.example; env keys CSR_*/CERTINEL_* -> CERTHEIM_* (read via the Phase-1 envcompat
    shim, so old env files keep working)
  - deploy.sh MANIFEST + verify.sh manifest + Containerfile + entrypoint + helm + frontend guide +
    docs/runbook + .gitlab-ci.yml (pg user, tmp dirs, unit lint, portal upload URLs)
  Migration (move + upgrade hook):
  - tools/certheim-migrate.sh: idempotent backup -> stop -> move dirs -> create certheim account +
    chown-remap -> rewrite env/nginx/sudoers -> SELinux relabel -> fapolicyd re-trust -> daemon-
    reload. Refuses ambiguous (both-layouts) state.
  - deploy.sh runs it automatically when it detects the legacy layout (never on --diff); legacy-
    unit retirement list extended with certinel-*.
  - Containerfile bakes the LEGACY env spellings (values = new paths) so a pod overriding a legacy
    var still wins; entrypoint keeps reading a legacy-mounted volume if present.
  Kept on purpose: /csr/ URL + /var/www/csr web root (semantic 'certificate signing request');
  OpenBao certinel-keys path + the openbao role default (external systems); the /certinel flat
  legacy image tags; CI variable NAMES (CERTINEL_*_SECRET); git history (CHANGELOG). Portal DB
  table/headers/endpoints are Phase 4.
  Gates: py_compile, bash -n (incl. certheim-migrate.sh), 95 pytest passed, RPM builds clean (0
  certinel-named files, renamed units/tools present).
  BREAKING for pre-5.2 installs — auto-migrated by deploy.sh/certheim-setup; rehearsed on disa in
  Phase 3 before the fleet. Propagates to Commercial/Government.

## 5.1.0 — 2026-07-09

_Released 2026-07-09. 1 change since community-v5.0.1._

### Features

- **rename-p1:** dual-read CERTHEIM_* env vars alongside legacy CSR_*/CERTINEL_* (`fce4366c`)
  Phase 1 of the certinel->certheim internal rename (docs/certheim-rename-design.md section 2): the
  app now reads every configuration variable under BOTH its canonical new spelling (CERTHEIM_*) and
  its legacy spelling (CSR_*/CERTINEL_*), canonical winning when both are set — so Phase 2's renamed
  code and Phase 3's migrated env files can land in any order without breaking a running install.
  - backend/envcompat.py: stdlib-only getenv() shim; maps CSR_X/CERTINEL_X <-> CERTHEIM_X (the two
    legacy namespaces never cross-consult). Removed in Phase 5.
  - all 41 direct os.environ.get("CSR_*"/"CERTINEL_*") call sites across 8 backend modules ->
    envcompat.getenv(); sign.py _cfg() (the ~20 indirect signing/ACME vars) and
    capabilities._flag() (CSR_CAP_* concat) covered too.
  - app.py _load_env_file(): the merged env-file dict gains the same overlay, so a CERTHEIM_-
    spelled key in certinel.env or the environment satisfies its legacy twin.
  - deploy.sh MANIFEST + verify.sh manifest ship the new module (a deploy without it would
    ImportError).
  - tests/test_envcompat.py (priority, fallback, namespace isolation, CAP concat) added to both CI
    smoke jobs.
  Verified: full smoke suite 83 passed locally; call-site equivalence proven for capabilities._flag
  and the db path expression under legacy vs canonical env.

## 5.0.1 — 2026-07-09

_Released 2026-07-09. 12 changes since community-v5.0.0._

### Fixes & improvements

- retry the doctor's health probe over gunicorn startup (`29ce13f3`)
  On a fresh install certinel-doctor runs immediately after certinel-api starts, and gunicorn may
  not have bound 127.0.0.1:5002 yet — so a perfectly healthy first install reports a false
  '/api/health did not return a version' FAIL (observed on both the AlmaLinux 10 and DISA-STIG RHEL
  10.2 RPM validation installs; the app answered 200 seconds later). Retry the probe up to 3x/2s,
  the same startup grace deploy.sh already gives its version check.
  Also cuts community-v5.0.1, whose publish step ships the first GPG-signed RPM to the licenses
  portal now that the signing CI variables are in place.

### Other changes

- **deps:** update docker.io/library/nginx docker tag to v1.31 (`4351c677`)
- rename design — keep /csr/ URL path (no URL change in any phase) (`a13b4c9f`)
- rebrand customer-side artifact names certinel -> certheim (`1bacc08e`)
- RPM install path for RHEL 9/10 incl. DISA STIG (`28851ad5`)
- full certinel->certheim internal rename (Phase 0) (`78b7b6e3`)
- GPG-sign the RPM for STIG / gpgcheck hosts (`ed8b824b`)
- build a native RPM (.rpm) for self-hosted install (`9a07bf9b`)
- push/pull certheim/<edition> nested image namespace (`e26ac61e`)
- rename helm chart certinel -> certheim (`4ba0cb3b`)
- **p4:** point entitled-registry + contact refs at certheim.com (`3f591ac7`)
- **mirror:** mirror the true Community tip so GitHub main never lags the release (`05b29120`)

## 5.0.0 — 2026-07-08

_Released 2026-07-08. 1 change since community-v4.1.1._

### Breaking changes

- publish v5.0.0 under the Certheim image namespace (`9492ea8`)
  Cuts the first Certheim platform generation (v5.0.0) and redirects the Docker Hub public image
  from docker.io/ac2solutions/certinel to docker.io/ac2solutions/certheim (HUB_IMAGE + customer-
  facing verify and licensing docs). Entitled registry registry.ac2certinel.com/certinel is left for
  Phase 4.
  ac2solutions/certinel to ac2solutions/certheim; existing pull references must be updated. This
  stamps the shared v5.0.0 major (the Certinel to Certheim rebrand generation), which propagates
  upward to Commercial and Government.

### Features

- publish v5.0.0 under the Certheim image namespace (`9492ea8`)
  Cuts the first Certheim platform generation (v5.0.0) and redirects the Docker Hub public image
  from docker.io/ac2solutions/certinel to docker.io/ac2solutions/certheim (HUB_IMAGE + customer-
  facing verify and licensing docs). Entitled registry registry.ac2certinel.com/certinel is left for
  Phase 4.
  ac2solutions/certinel to ac2solutions/certheim; existing pull references must be updated. This
  stamps the shared v5.0.0 major (the Certinel to Certheim rebrand generation), which propagates
  upward to Commercial and Government.

## 4.1.1 — 2026-07-08

_Released 2026-07-08. 5 changes since community-v4.1.0._

### Fixes & improvements

- **gitleaks:** global allowlist is [allowlist] not [[allowlist]] (`2d3728d`)
  gitleaks v8 expects the top-level allowlist as a single table; the array form failed config load
  ('Allowlist expected a map, got slice'), which made the mirror-github gate error out before
  pushing (fail-safe — nothing was published). Verified: config loads and reports 0 leaks over full
  history.

### Other changes

- AGPLv3 Community + gated GitHub mirror (`24c4e75`)
- Certinel → Certheim (brand-facing surfaces), v5.0.0 (`2a48527`)
- point pull paths at the per-edition entitled repos (certinel/<edition>) (`990d606`)
- publish per-edition repos to the entitled registry (certinel/<edition>) (`3756862`)

## 4.1.0 — 2026-07-06

_Released 2026-07-06. 1 change since community-v4.0.1._

### Features

- surface valid-license-on-lower-tier-build mismatch (`3e978a1`)
  A Commercial/Government license installed on a Community (or otherwise lower-tier) build cannot
  enable premium features — that code isn't in the artifact (build = ceiling, license = key).
  Previously the app reported the LICENSE edition, so a Commercial license on a Community build
  claimed "Commercial edition" while nothing was actually on, leaving the operator confused.
  licensing.build_mismatch() detects when a valid license out-ranks the build and returns an
  actionable upgrade message (redeploy with the edition image using the registry pull credentials
  from the license email). info() now carries build_edition + edition_mismatch (and folds the
  message into warnings); the boot banner reports the BUILD ceiling on mismatch; /api/me exposes it;
  the Admin -> License page shows a warning callout + a "<edition> license · <build> build" pill,
  and the header edition badge names the running build tier instead of the inactive license tier.
  Test: test_license_build_edition_mismatch covers Commercial-on-Community (mismatch + /api/me),
  Commercial-on-Commercial (clean), Government-on-Commercial.

## 4.0.1 — 2026-07-06

_Released 2026-07-06. 1 change since community-v4.0.0._

### Fixes & improvements

- **release:** re-align upper editions to a Community-cut major on propagation (`9829b7a`)
  release.sh documented that a Community major "sweeps upward via propagation (every edition re-
  aligns on vN.0.0)", but no code implemented it: the major-from-base-only clamp turned an up-tier
  breaking change into a MINOR and stopped, leaving Commercial/Government a major behind forever
  (e.g. after Community v4.0.0, Commercial cut 3.77.0 instead of 4.0.0).
  Adds the missing step: a non-community edition whose base line (editions/community.version) has a
  higher MAJOR than the edition's last tag now adopts vMAJOR.0.0. Same-major editions are
  unaffected. Verified the arithmetic for both cases.

## 4.0.0 — 2026-07-06

_Released 2026-07-06. 3 changes since community-v3.27.1._

### Breaking changes

- Commercial is a flat, unlimited plan — no per-domain cap (`3fdcc80`)
  Pricing/packaging change: Commercial is now sold as a single flat plan ($5k/mo, unlimited domains)
  with support/HSM/onboarding as add-ons, replacing the per-domain metering. Backend:
  _default_max_domains() now returns 0 (unlimited) for every edition — Commercial included. A
  license may still carry an explicit max_domains to cap a bespoke deployment, and the enforcement
  mechanism (domains.py + sign._enforce_domain_quota) is retained and still tested for that case.
  "unlimited" stays a valid edition string, now equivalent to Commercial.
  Updated the domain-quota smoke test: Commercial defaults to uncapped; the cap path is now
  exercised via an explicit-max_domains license. Comments in licensing/capabilities/domains updated.
  75 smoke tests pass.
  at one registrable domain). Existing Commercial deployments gain unlimited domains on upgrade.
  This is the v4.0.0 line across all editions.

### Features

- Commercial is a flat, unlimited plan — no per-domain cap (`3fdcc80`)
  Pricing/packaging change: Commercial is now sold as a single flat plan ($5k/mo, unlimited domains)
  with support/HSM/onboarding as add-ons, replacing the per-domain metering. Backend:
  _default_max_domains() now returns 0 (unlimited) for every edition — Commercial included. A
  license may still carry an explicit max_domains to cap a bespoke deployment, and the enforcement
  mechanism (domains.py + sign._enforce_domain_quota) is retained and still tested for that case.
  "unlimited" stays a valid edition string, now equivalent to Commercial.
  Updated the domain-quota smoke test: Commercial defaults to uncapped; the cap path is now
  exercised via an explicit-max_domains license. Comments in licensing/capabilities/domains updated.
  75 smoke tests pass.
  at one registrable domain). Existing Commercial deployments gain unlimited domains on upgrade.
  This is the v4.0.0 line across all editions.

### Other changes

- **nginx:** server_tokens off + security headers (HSTS, nosniff, frame-deny, referrer) (`dc18f20`)
- **ops:** tested backup / restore / upgrade / disaster-recovery runbook (`234c161`)

## 3.27.1 — 2026-07-05

_Released 2026-07-05. 2 changes since community-v3.27.0._

### Fixes & improvements

- **rhel:** return 422 (not 500) when generation fails (`35626a8`)
  POST /api/rhel/generate returned 500 when the helper's generate-typed failed (bad cert type /
  missing CSR-subject config). A generation failure is an unprocessable request, not an internal
  server fault — 500 reads as an app bug and trips uptime monitors. Return 422 with a clear message
  + the helper output. Smoke test asserts empty input is 4xx, never 5xx.

### Other changes

- isolate test_support_bundle from the shared-process smoke harness (`75746cb`)

## 3.27.0 — 2026-07-05

_Released 2026-07-05. 7 changes since community-v3.26.1._

### Features

- **launch:** security-disclosure policy, release verification, support bundle, ASN.1 fuzz tests (`78cabbf`)
  Pre-launch hardening pass (edition-agnostic, so on Community → propagates up):
  Disclosure + supply-chain docs
  - SECURITY.md — vulnerability disclosure policy: security@ contact, CVSS-based triage SLAs
    (3-day ack / 30-day critical fix), coordinated-disclosure window, researcher safe harbor, and
    scope.
  - docs/verifying-releases.md — how customers verify what they run: inspect the BuildKit SBOM +
    SLSA provenance attestations (buildx imagetools / cosign), pin by digest, and check tarball
    SHA-256.
  - NOTICE + docs/third-party-licenses.md — third-party license inventory, with the psycopg LGPL
    obligation called out explicitly (used unmodified, dynamic, Postgres-only).
  Support bundle (all editions)
  - backend/support_bundle.py + GET /api/admin/support-bundle (admin-only) + an Overview button.
    Assembles a ZIP of version/edition/env, capability + FIPS posture, DB schema SHAPE (table row-
    counts, never row data), a recent audit tail, and app settings with every secret VALUE
    redacted. Deny-by-default redaction: any credential-shaped key OR credential-shaped value is
    masked, so a newly-added secret setting can't leak by being unlisted. Cuts support cost for
    air-gapped installs where we can't see anything.
  Security regression tests
  - tests/test_support_bundle.py — proves no secret value appears in the DECOMPRESSED bundle while
    benign settings survive (checking raw zip bytes would be meaningless — deflate hides
    plaintext; that bug was caught + fixed).
  - tests/test_asn1_fuzz.py — robustness fuzzing of the three unauthenticated ASN.1 parsers (SCEP
    /scep, EST /.well-known/est, CMP /cmp): ~2000 malformed inputs (length/indefinite-length
    bombs, a nesting bomb, truncations, byte-flips) must fail with a controlled error, never an
    unhandled crash, Recursion/Memory error, or hang. Verified 0 findings against the live
    Commercial parsers; skips where the premium modules/asn1crypto are absent.

### Other changes

- **guide:** per-option setup steps for Integrations + Email, with filters (`6ed5fb0`)
- **guide:** per-backend setup steps on the Signing/CA "?" page, with a filter (`61ff164`)
- **setup-guide:** add advanced-features section (encrypted keystore, EST/SCEP, code-signing+TSA, DNSSEC) (`e72b787`)
- **release:** cap image builds with timeout + retry so a base-image pull stall can't wedge the pipeline (`28626f4`)
- auto-retry jobs on transient runner failures (`d552bb1`)
- **guide:** make signing docs reflect ACME-free Community; add proxy note (`541b87c`)

## 3.26.1 — 2026-07-02

_Released 2026-07-02. 1 change since community-v3.26.0._

### Fixes & improvements

- **deploy:** proxy the ACME server, /metrics and SCIM through nginx (`a6803cc`)
  The in-pod (helm) and VM nginx only proxied /csr/api/ to the app; everything else fell through to
  the SPA catch-all. Three premium endpoints the app serves for EXTERNAL clients live on their own
  top-level paths — the ACME server (/acme/*, RFC 8555), Prometheus /metrics, and SCIM 2.0
  (/scim/v2/*) — so an external certbot/cert-manager, Prometheus scrape, or IdP SCIM push hit the
  HTML shell instead of the handler. The features' advertised URLs could never work even once an
  admin enabled them.
  Add proxy_pass locations for /acme/, /metrics, and /scim/ to the helm ConfigMap, the VM nginx
  snippet, and the setup-guide config generator so generated deployments are correct too.
  Editions/deployments without a given feature just return 404/disabled from the app, so the blocks
  are safe everywhere.

## 3.26.0 — 2026-07-02

_Released 2026-07-02. 2 changes since community-v3.25.1._

### Features

- **signing:** Community signing is manual + ACME only; gate OpenBao (`8883fdd`)
  Per product direction, the free Community tier's in-UI signing is the ACME client (any RFC 8555
  CA) plus manual cert upload — nothing else. OpenBao, the enterprise secret-manager CA, moves into
  the Commercial capability set alongside the other paid backends (Windows/CyberArk/EJBCA/Venafi/AWS
  PCA).
  Effect on the Signing/CA admin panel (Community only):
  - OpenBao now reports capability.upgrade=true, so the existing gray-out logic disables + badges
    it "Commercial" in the backend dropdown, leaving only Manual and ACME selectable.
  - The connection-settings form is never rendered for a gated backend: if a gated backend is
    somehow the selected/default value, the picker falls back to Manual and _signingRenderProvider
    shows an upgrade note instead of the fields — admins can't even view a paid backend's
    connection settings.
  Commercial/Government are unaffected: their license entitles OpenBao, so it reads "needs <env>"
  (configurable), not "upgrade", and is not grayed.

### Fixes & improvements

- **signing:** gate the signing core on capabilities, not a stale build tuple (`5894025`)
  sign.py's sign_csr/test_connection hard-coded the Community-allowed backends as ("manual",
  "openbao") — written before ACME became the free Community signing path. That left two
  contradictions on Community: ACME (the advertised free backend) was REFUSED by the core ("acme is
  a licensed signing backend"), while OpenBao (now premium, grayed in the UI) was still ALLOWED. So
  the one backend the UI offers didn't work and the one it hides did.
  Replace both hard-coded gates with `capabilities.is_entitled("ca.signing." + backend)`, which
  folds the license AND the build ceiling into one check: ACME passes on Community (free), OpenBao +
  the enterprise backends are refused (premium / code absent), and Commercial/Government keep
  everything their license grants. This reconciles the signing core with the capability layer and
  the frontend gray-out.
  Template/global signing CONFIG stays intentionally decoupled from license (you can pre-pin a
  backend before applying a license — see test_template_pin_enterprise_backend); enforcement is at
  sign time only.
  Regression test: test_sign_core_gate_matches_capabilities.

## 3.25.1 — 2026-07-02

_Released 2026-07-02. 1 change since community-v3.25.0._

### Fixes & improvements

- **ci:** retry the entitled-registry mirror and fail loud on miss (`40732fb`)
  The release job mirrors each edition's image from Docker Hub into the entitled registry
  (registry.ac2certinel.com) that the K8s pods pull from. That push is over the plain-HTTP LAN
  origin and occasionally fails; the failure was swallowed by `|| echo "note: ...skipped/failed"`,
  so the job stayed green while the pods silently lagged a release behind (this is exactly what
  stranded community/commercial/government one version back — the -latest tags never advanced and
  the newest images 404 in the registry).
  Now the mirror push is retried up to 3x with backoff, and a genuine miss records a flag that fails
  the job LOUD at the end — after Docker Hub, the GitLab release/tag, and the offline bundle have
  all published, so only the re-runnable edition-propagation stage is gated. This re-release also
  re-mirrors the current build, healing the stranded registry tags.

## 3.25.0 — 2026-07-02

_Released 2026-07-02. 1 change since community-v3.24.0._

### Features

- **ui:** gray out upgrade-gated features on the Community edition (`5c15574`)
  On the free Community build, licensed features this build physically cannot run are now disabled
  and badged "Commercial" in the admin UI, so admins don't burn time configuring backends that can
  never work here. Covers the real dead-ends: the signing/CA backend pickers (global + per-
  template), delivery destinations, automated renewal, and the ACME server toggle. The free OpenBao
  and ACME-client backends are never gated.
  Deliberately scoped to the Community edition only: Commercial/Government keep these controls live
  because they can genuinely license/configure them (their capabilities read "needs <env>", not
  "upgrade"). The gate keys off capability.upgrade (build/edition gating), NOT .available (which
  folds in env config) — otherwise a free-but-unconfigured backend like OpenBao would be wrongly
  grayed on Community.
  Client-side only; no backend or capability changes.

## 3.24.0 — 2026-07-02

_Released 2026-07-02. 1 change since community-v3.23.4._

### Features

- **signing:** ship the ACME client as a free Community backend (`a0bc898`)
  Obtaining certs FROM an external ACME CA (Let's Encrypt / step-ca / any RFC 8555 CA) uses a free,
  open protocol, so gating the ACME *client* as Commercial was hard to justify. It now ships free
  with Community alongside the OpenBao backend: the core client (acme_client.py — HTTP-01 + internal
  DNS-01/rfc2136) is included in the Community build and ca.signing.acme is removed from the
  licensed capability set.
  Held back as premium (unchanged): the cloud DNS-01 solvers (acme_dns.py —
  Cloudflare/Route53/Azure) and the ACME *server* (ca.server.acme). On a build without acme_dns, the
  admin UI advertises only the free challenge paths and a cloud-provider selection fails with a
  clear "requires Commercial" SignError rather than an ImportError.
  Edition-robust tests: test_community_acme.py plus a shape fix in the smoke suite (both branch on
  whether acme_dns physically ships).

## 3.23.4 — 2026-06-30

_Released 2026-06-30. 1 change since community-v3.23.3._

### Fixes & improvements

- ship per-edition version file in the image so it reports the true version (`b59f2da8`)
  The Containerfile copied backend/ + the root VERSION but never the editions/ dir. _read_version()
  prefers editions/<edition>.version (chosen by build_mode.EDITION) and falls back to root VERSION —
  which release.sh only ever writes from the community release (the base line). So
  Commercial/Government images shipped no editions/<edition>.version and reported the community
  number (e.g. clm showed 3.23.3 instead of commercial 3.61.4), even though the build, modules,
  license and behavior were all correct.
  Fix: COPY editions/ into the image. Each branch carries only its own .version, so community still
  resolves community.version; commercial/government now resolve their own. .md changelogs stay
  excluded by .containerignore, so only the tiny *.version files are added.

## 3.23.3 — 2026-06-29

_Released 2026-06-29. 2 changes since community-v3.23.2._

### Fixes & improvements

- enforce object-level authz on job read/list/upload endpoints (`f1a70689`)
  The job read surface was scoped only at the action level (can_* flags), never as a visibility
  filter, so any authenticated user could:
  - GET /api/jobs            list every user's jobs (hosts, emails, status) and filter by
    ?requester= to target a person
  - GET /api/jobs/<id>[/csr|/csr-info|/cert|/cert-info]  read any job + CSR
  - GET /api/jobs/export.csv          export the whole catalogue
  - GET /api/signing-queue/csrs.zip   bulk-download every pending CSR
  - POST /api/jobs/<id>/upload-cert   attach a cert to ANY pending job (write IDOR: forces it to
    'issued', fires delivery/webhook/email on someone else's job)
  Add a single visibility model mirroring the existing per-action authz (get_job_key, _row_to_job):
  signers and admins see the whole queue (the signing/oversight workflow needs it); everyone else is
  scoped to their own and their groups' jobs. list/export get a SQL predicate; the per-job reads and
  upload-cert get an object-level 403 gate; the signing-queue zip is restricted to signer/admin.
  Verified live on clm: non-owner now 403/empty on all paths; owner sees own jobs; admin/signer
  retain full visibility.

### Other changes

- black-box security authz battery (IDOR + round-trip + XSS) (`1466a520`)

## 3.23.2 — 2026-06-29

_Released 2026-06-29. 1 change since community-v3.23.1._

### Fixes & improvements

- container-mode hardening (audit log, config paths, error bodies, trust/helper) (`ce2a6ef0`)
  Bugs found auditing the k8s container deployment (sudo-less, non-root, no syslog), all hot-patched
  live on clm and now made durable:
  - audit logger fell back to a missing /dev/log SysLogHandler -> FileNotFoundError flood on every
    event + lost audit stream; use stdout when /dev/log is absent.
  - email (notify) + chat (gitlab_integration) config lived under /etc/certinel, which is NOT a
    volume -> lost on restart; move to /var/opt/certinel (PVC).
  - error handler returned {error:'internal error'} for every status incl 404; return a code-
    appropriate message for 4xx.
  - truststore install-local ran a root-only update-ca-trust; guard with a clear message in
    container mode (remote SSH/pull installs unaffected).
  - chown-issued did an unconditional chown ansible:ansible (fails every issuance in-container);
    no-op unless root + user exists.
  (SAML metadata 503->404 is Commercial+-only code, handled in a separate MR.)

## 3.23.1 — 2026-06-29

_Released 2026-06-29. 2 changes since community-v3.23.0._

### Fixes & improvements

- force a clean venv in smoke-test CI jobs (`964a5997`)
  The shell runner reuses /tmp/cienv between pipelines; after a runner Python upgrade the cached
  venv's pip broke (ModuleNotFoundError pip._internal.cli.main) and plain 'venv' won't rebuild an
  existing dir. Add --clear so each run gets a fresh, matching pip. Same for the postgres job's
  /tmp/cienv-pg.
- publish a per-edition <edition>-latest image tag (`f67160cf`)
  Add an explicit always-latest pointer per edition alongside the existing moving tag: each release
  now also pushes 'certinel:<edition>-latest' (and '-latest-slim') to both Docker Hub and the
  entitled registry, so consumers can pull community-latest / commercial-latest / government-latest
  and always get the newest of that edition without tracking version numbers.

## 3.23.0 — 2026-06-27

_Released 2026-06-27. 7 changes since community-v3.22.0._

### Features

- cert-type selection as tiles with EKU help tooltips (`e0a86412`)
  Make the template/request cert-type pickers easier to scan and use:
  - Each type is a click-anywhere tile (the native checkbox is hidden but kept, so all selection +
    exclusivity logic is unchanged); selected tiles highlight.
  - A '?' in each tile corner shows a custom tooltip (instant on hover, click to pin) explaining
    what the type is for and its EKU — covers all cert-type grids.
  - 3-up layout (far-left / middle / far-right), collapsing to 2 then 1 column on smaller screens;
    long names no longer wrap.
  Frontend only (app.1-core.js + app.css).

### Other changes

- container-safe file ownership (sudo-less mode) (`c136c186`)
- accept service-user-owned parts in container mode (`9fc5ec0c`)
- make the UI mobile-responsive (`baf298c2`)
- C3.3 SSO design - dependency-free OIDC + vetted-library SAML (`26c30749`)
- record C3.2/C3.3 decisions - hard tenant isolation + vetted SSO library (`8d5e3c0f`)
- C3 governance design (RBAC/tenancy/SSO/SCIM) + mark C2 shipped (`2d29a122`)

## 3.22.0 — 2026-06-24

_Released 2026-06-24. 3 changes since community-v3.21.0._

### Features

- **alerts:** delegate run_expiry_warnings to the inventory alerting engine (`419911a`)
  When the alerts module is present (Commercial+) and visibility.inventory is entitled,
  run_expiry_warnings hands off to the inventory-wide engine (alerts.run_alerts), giving one alert
  path with no double-notification. Guarded by ImportError, so the Community build (no alerts
  module) runs the base jobs-only pass unchanged. Pairs with the C2.2 engine MR on Commercial.

### Other changes

- C2 outage-prevention design + mark C1 shipped (`406119f`)
- add product ROADMAP + C1 visibility-inventory design (`af83661`)

## 3.21.0 — 2026-06-23

_Released 2026-06-23. 13 changes in the initial release._

### Features

- **release:** per-edition versioning with Community-owned major (`bea7c6f`)
  Move releases from a single trunk to a per-edition model that matches the Community -> Commercial
  -> Government branch stack:
  - release.sh is edition-aware: each edition cuts from its OWN tag namespace (community-v* /
    commercial-v* / government-v*) into its own editions/<edition>.version +
    editions/<edition>.changelog.md, continuing from the legacy v* line on first release.
  - MAJOR is owned by Community only: a breaking change up-tier clamps to a MINOR, so all editions
    stay on the same platform generation; a Community-cut major sweeps upward and re-aligns
    everyone on vN.0.0.
  - CI release job fires per edition branch (was default-branch only) and tags + publishes
    edition-scoped images (<edition>-vX.Y.Z + rolling <edition>; Community also keeps bare
    latest/slim and is the sole offline-bundle publisher).
  - Each edition writes only its own files (only Community writes root VERSION), so bottom-up
    propagation never conflicts on release accounting. .gitattributes adds union as belt-and-
    suspenders; build_mode EDITION stays a documented manual-resolve.
  - app.py reports the running edition's version; deploy.sh materializes it into root VERSION;
    make-offline-bundle reads the community line.
  - RELEASING.md rewritten for the per-edition + major-from-base model.
- **editions:** tier-aware build ceiling (community/commercial/government) (`4141727`)
  Generalizes the Community force-deny into a build-edition ladder shared by all tiers.
  build_mode.EDITION (set per branch) ranks community(0) < commercial(1) < government(2) < full(3);
  capabilities gates each licensed capability by the build tier that physically contains its code,
  as a hard CEILING on top of the license:
  - community build  -> no premium at all
  - commercial build -> commercial premium, no gov pack
  - government build -> everything The license is still required on top (build = ceiling, license
    = key). This logic lives on the Community base so it merges upward into Commercial/Government,
    which only flip the EDITION constant.
- **community:** strip premium code into a free Community build (`cdd0733`)
  Physically removes the premium modules so there is no gate to crack — the paid code simply isn't
  present in this build: ca_providers, acme_client, acme_dns, acme_server, routes_acme, deliver,
  routes_deliver, renew, slack_listener
  - build_mode.EDITION='community' + is_community_build(): the surviving core force-denies every
    licensed capability regardless of any license file.
  - capabilities.status() now returns an 'upgrade' flag so the UI can gray out premium features as
    upsell instead of hiding them (19 caps flagged).
  - Soft imports / guards everywhere a free path referenced a premium module (app.py deliver+renew
    re-exports & blueprints; sign.py premium signing backends refused; routes_admin delivery/auto-
    renew; truststore SSH push).
  - Free tier intact: OpenBao signing, on-demand re-sign, trust store, fleet/ audit/SMTP/local
    auth, CSR generation.
  Verified: py_compile all; app boots with premium absent; premium routes=0; ejbca signing refused;
  openbao provider intact; capability upgrade-flags=19.
  Follow-ups: frontend gray-out (consume the upgrade flag), strip the inline premium signing
  providers still in sign.py (cyberark/windows/acme dispatch; runtime-refused but code present),
  two-target CI build, upgrade-in-place deploy.

### Fixes & improvements

- **auth:** keep auth_mode default = mtls (edition default is a deploy concern) (`3525405`)
  The edition-aware runtime default broke 36 smoke tests that assume the mtls default. Revert to the
  original. The fresh-Commercial-tries-CAC issue is handled at deploy time instead (install sets
  auth_mode=local for non-government editions), which the running demo instances already have. Keeps
  the banner-edition fix.
- **auth:** read auth_mode raw so the edition-aware default applies (`01cadd5`)
  get_setting('auth_mode') masks 'unset' as the _SETTINGS_DEFAULTS 'mtls', so the previous fix never
  triggered. Read app_settings directly: an explicit admin choice wins; otherwise default to mtls
  only when auth.cac is entitled (gov build + gov license), else local. Fixes Commercial/Community
  trying CAC on a fresh box.
- **auth:** default auth_mode to local unless CAC is entitled (`0c4c4a3`)
  A fresh box with no auth_mode setting defaulted to 'mtls', so Community and Commercial builds
  (where auth.cac is not entitled) tried to authenticate with CAC they can't satisfy. Default to
  mtls only when capabilities.is_entitled ('auth.cac') (a government build + gov license); otherwise
  local.
- startup banner shows the actual build edition, not hardcoded 'Community' (`afda4bd`)
  The unlicensed-startup warning hardcoded 'Community' even on commercial/government builds. Print
  build_mode.EDITION so each edition logs its true identity.
- **community:** drop stripped premium files from deploy/verify manifests (`259cf42`)
  deploy.sh and verify.sh listed the now-deleted premium modules (deliver, renew,
  acme_client/dns/server, ca_providers, routes_acme/deliver); trim them so the Community build
  deploys + verifies clean.

### Other changes

- remove demo propagation footers from Community (`ba78390`)
- add removable 'community' footer to propagate up the editions (`1f2c3b8`)
- **editions:** skip higher-tier smoke tests on lower builds (`614cad3`)
- **editions:** bottom-up propagation job (Community -> Commercial -> Government) (`1865464`)
- publish the offline installer bundle to the licenses portal on release (`9c9de4d`)

