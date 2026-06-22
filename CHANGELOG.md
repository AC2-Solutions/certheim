# Changelog

All notable changes to the CSR Dashboard. Versions track the `VERSION` file
(the app reports it at `/api/health` and on the admin Overview tile).

## 3.15.2 — 2026-06-22

_Released 2026-06-22. 1 change since v3.15.1._

### Fixes & improvements

- **db:** init_db mkdir uses configured sqlite path; validate Postgres e2e (`da33589`)
  Stood up Postgres 17 and ran the full smoke suite (104/104) against the db.py abstraction - the PG
  path was scaffolded (db.py shim, requirements-postgres.txt, the smoke-tests-postgres CI job) but
  never actually validated end-to-end.
  One real bug surfaced: init_db() mkdir'd the parent of the IMPORT-TIME DB_PATH global (frozen to
  /var/lib/certinel), not the currently-configured sqlite path. The migration tool reconfigures dbx
  to a target path before init_db(), and a Postgres deployment never sets CSR_DB_PATH, so the stale
  default could be unwritable -> PermissionError. Now mkdir dbx.sqlite_path() (still skipped
  entirely in Postgres mode). 104/104 on both backends, fresh DB.
  Also: the smoke fixture now honors a pre-set CSR_DB_URL/CSR_DB_BACKEND so the same suite runs
  unchanged on both backends (the CI db-matrix), and document the CSR_DB_* Postgres vars in
  certinel.env.example.

## 3.15.1 — 2026-06-22

_Released 2026-06-22. 1 change since v3.15.0._

### Fixes & improvements

- **installer:** robust Python detection + fapolicyd parity on online install (`7e80078`)
  PYBIN auto-detect matched a name on PATH without running it, so a dangling symlink or a sub-3.9
  interpreter could win; now probe each candidate and require >=3.9 (online-install.sh). The offline
  bundle hardcoded python3.9 for the wheelhouse AND in the generated target scripts, so an Alma 9
  host updated to 3.12 got 3.9 wheels it couldn't load; build with the best Python on the host and
  bake that exact pythonX.Y into START_HERE + offline-install.sh.
  Also add fapolicyd venv trust to online-install.sh - the offline installer already trusts
  /opt/certinel/venv; the online path skipped it, so the service couldn't exec gunicorn/python on
  STIG hosts after an online install.

## 3.15.0 — 2026-06-22

_Released 2026-06-22. 1 change since v3.14.0._

### Features

- point chart/compose/setup-guide at the entitled registry (`d937229`)
  Customer-facing image refs now resolve to the entitled Certinel registry
  (registry.ac2certinel.com/certinel), where pull is gated by the customer's license (the final step
  of entitled-pull). Updates:
  - helm values: image.repository -> registry.ac2certinel.com/certinel; tag default 'latest' (the
    appVersion default never matched the published :vX.Y.Z scheme); pullSecrets [{name: regcred}]
    since the registry now requires the license credential.
  - setup-guide generator: compose + helm values use the entitled registry + pullSecrets; the k8s
    secret + a new compose 'docker login' step use the license id + pull token (from the License
    portal) as the registry credential.
  Validated: helm lint + template (image + regcred render), generator emits valid YAML, HTML
  balanced, no stale customer-facing refs.

## 3.14.0 — 2026-06-22

_Released 2026-06-22. 1 change since v3.13.2._

### Features

- **ci:** mirror attested images into the entitled Certinel registry (`1699be3`)
  After publishing to Docker Hub, the release job now also pushes the same attested UBI9 + slim
  images into the entitled registry on the license-server origin (192.168.201.19:5000), over the LAN
  — bypassing Cloudflare's 100MB request-body cap (customer pulls go through the tunnel; the mirror
  push does not). Auth via the _mirror push credential on the portal token endpoint
  (CERTINEL_MIRROR_PUSH_SECRET); registry.insecure because the origin is plain HTTP on the LAN
  (Cloudflare terminates TLS for pulls). Non-fatal: a mirror hiccup never undoes the Docker Hub
  publish. Gated on CERTINEL_MIRROR_PUSH_SECRET being set.

## 3.13.2 — 2026-06-22

_Released 2026-06-22. 2 changes since v3.13.1._

### Fixes & improvements

- accept Windows DER (.cer) and PKCS#7 (.p7b) on manual cert upload (`e3f0104`)
  Windows CAs hand back DER-encoded .cer files (binary) and sometimes PKCS#7 .p7b bundles; the
  manual upload path only accepted PEM, and two bugs stacked:
  - frontend read the file with FileReader.readAsText(), which mangles binary irreversibly before
    it leaves the browser
  - backend validated with 'openssl x509 -subject' assuming PEM, so DER/ PKCS#7 was rejected
  Fix: the client reads the file as base64 (readAsDataURL) and sends it as a separate cert_b64 field
  (pasted PEM still flows through cert_pem); the server adds _normalize_cert_to_pem() which converts
  PEM/DER/PKCS#7 -> PEM via openssl before the unchanged pipeline (subject parse, pubkey match,
  expiry, storage) runs. Decoded-byte size check; binary files show a placeholder instead of
  garbage; b64 holder resets per dialog open. File picker now advertises .der/.p7b.
  Smoke test covers PEM/DER/PKCS#7 round-trips + garbage rejection (104 pass); node --check +
  pyflakes clean.

### Other changes

- design for entitled-pull container licensing (`96e1b1a`)

## 3.13.1 — 2026-06-22

_Released 2026-06-22. 2 changes since v3.13.0._

### Fixes & improvements

- **ci:** keep rootless BuildKit state out of the git workspace (`cc4c561`)
  The release job's rootless buildkitd writes runc-overlayfs snapshots owned by remapped subuids
  (build uid 10001 -> host subuid range). When that state sat in $CI_PROJECT_DIR/.bk, a plain rm
  couldn't delete it and the NEXT pipeline's get_sources (git clean -ffdx) failed with Permission
  denied. Move it to $TMPDIR/certinel-bk-$CI_JOB_ID (outside the build dir) and clean via 'buildah
  unshare -- rm -rf' (userns maps the subuids back). Stale dirs from prior runs cleared on the
  runner by hand.
- slim the UBI9 image base to cut Docker Scout vulnerabilities (`e3ed93f`)
  Docker Scout on ac2solutions/certinel:latest showed 9 fixable High CVEs, nearly all from the base
  image rather than our code:
  - ubi9/python-312 is the s2i builder variant and ships a full npm/node toolchain we don't use
    (picomatch + ~570 npm packages) plus older system-python urllib3 1.26.5 / setuptools 53.0.0
  - our venv carried setuptools 68.2.2 (2 fixable High)
  Switch the default base to ubi9/python-312-minimal (no s2i/npm layer) and upgrade pip+setuptools
  in the builder venv. Proven on the runner: builds, runs non-root uid=10001, /api/health ok, NO
  node/npm present, venv setuptools 82.0.1, image 422MB -> 279MB. Gov/FIPS keeps UBI9 as default;
  this just drops the unused toolchain. Slim variant unchanged.

## 3.13.0 — 2026-06-22

_Released 2026-06-22. 1 change since v3.12.2._

### Features

- build release images with rootless BuildKit + SBOM/provenance attestations (`3f0e73a`)
  Docker Scout flagged 'Missing supply chain attestation(s)'. buildah can't emit the OCI attestation
  manifests Scout reads, so switch the release image build to rootless BuildKit (buildctl-
  daemonless.sh, provisioned on the runner by the ansible gitlab_runner_host role).
  Each published image now carries an SBOM (buildkit-syft-scanner) and SLSA provenance (mode=max)
  attestation: buildctl build --opt attest:sbom=true --opt attest:provenance=mode=max Build both
  UBI9 (default) + slim and push all four tags to docker.io/ac2solutions/certinel. /usr/local/bin is
  prepended to PATH (not on the runner default). Auth via a job-local DOCKER_CONFIG built from the
  instance DOCKERHUB_USERNAME/_TOKEN. Falls back to buildah (no attestations) if BuildKit isn't
  present, and stays non-fatal so a build hiccup never undoes the cut tag. Drops the internal slim
  mirror (Docker Hub is canonical; the repo is private so LAN pulls authenticate anyway).
  Proven on the runner: rootless buildctl builds the real UBI9 + slim Containerfile and exports 2
  in-toto attestation layers (SBOM+provenance) with image User=10001; outbound docker.io pull/push
  path works.

## 3.12.2 — 2026-06-22

_Released 2026-06-22. 1 change since v3.12.1._

### Fixes & improvements

- run container image as non-root uid 10001 (Docker Scout hardening) (`273bf80`)
  Docker Scout flagged 'No default non-root user found'. Add a non-root user (uid/gid 10001) to the
  image and default to it:
  - create the user portably (useradd on both UBI9 + Debian-slim, numeric fallback), own
    /opt/certinel + the writable data/config paths, chown BEFORE the VOLUME line so a fresh
    Docker/Podman named volume inherits 10001 ownership; USER 10001 before the entrypoint
  - gunicorn binds :5002 (unprivileged); the helper runs sudo-less in container mode, owned by
    10001
  Chart side so non-root works on k8s with RWO PVCs:
  - podSecurityContext.fsGroup: 10001 (kubelet chowns the PVCs)
  - app + cronjob securityContext: runAsNonRoot, runAsUser 10001, allowPrivilegeEscalation false,
    drop ALL caps, seccomp RuntimeDefault (the nginx sidecar keeps its stock defaults)

## 3.12.1 — 2026-06-22

_Released 2026-06-22. 1 change since v3.12.0._

### Fixes & improvements

- publish container images to Docker Hub (ac2solutions/certinel) (`6d7332b`)
  The internal GitLab registry (registry.ac2solutions.com) is Cloudflare-proxied, and Cloudflare
  caps request bodies at 100 MB on non-Enterprise plans. The full UBI9 image has a layer over that
  limit, so its push silently failed with HTTP 413 on every release (the build block is non-fatal) —
  only the Debian-slim variant ever published. The default/FIPS-gov image was never actually
  available to pull.
  Switch the release job's image publish to Docker Hub, the canonical public registry for Certinel
  (anonymous customer pull, no body cap), matching the AethonLog docker.io/ac2solutions convention:
  - build UBI9 + slim, push :vX.Y.Z / :latest / :vX.Y.Z-slim / :slim to
    docker.io/ac2solutions/certinel, authenticating with the instance-level DOCKERHUB_USERNAME /
    DOCKERHUB_TOKEN
  - best-effort mirror of the slim variant to the internal GitLab registry for LAN pulls (small
    enough to clear the CF cap); never fatal
  - skip cleanly with a note when DOCKERHUB_TOKEN is unset
  Repoint the customer-facing image references to Docker Hub:
  - deploy/helm/certinel/values.yaml image.repository
  - setup-guide compose + helm-values generators (IMAGE / genValues)
  Validated: .gitlab-ci.yml parses, release script passes bash -n, and the setup-guide generators
  still emit valid YAML carrying the new image path.

## 3.12.0 — 2026-06-22

_Released 2026-06-22. 1 change since v3.11.0._

### Features

- setup-guide deployment generator for VM / container / k8s (`13269ad`)
  Phase 5 of the Deploy Anywhere release. The setup guide gains a 'How do you want to run Certinel?'
  selector (single-server VM / container / Kubernetes) plus a database-backend selector (built-in
  SQLite / external PostgreSQL, with a DSN field).
  The Install step now re-tailors itself to the chosen target and emits ready-to-run, fully-filled-
  in artifacts straight from the operator's entered settings, with copy + one-click download:
  - VM        -> the existing unattended online-install.sh command
  - container -> a complete docker/podman compose.yaml (app + nginx front + optional bundled
    PostgreSQL), valves wired for OpenBao + license
  - k8s       -> a tailored Helm values.yaml + the helm upgrade --install command, mapping 1:1 to
    the certinel chart (ingress host, clientCert for CAC, db.backend, openbao.*, license)
  - all       -> a single dependency-free Ansible playbook (certinel-deploy.yml) pre-set to the
    chosen method, branching vm/container/k8s with ansible.builtin only
  VM-only shell steps (first-admin bootstrap, OpenBao env file) are now guarded per method, with
  container/k8s equivalents shown inline.
  Generators validated: inline JS parses (esprima); all five method/db/auth/edition scenarios emit
  YAML that round-trips through a parser for compose, values, and playbook; values keys map to the
  chart schema verified in Phase 4.

## 3.11.0 — 2026-06-22

_Released 2026-06-22. 1 change since v3.10.0._

### Features

- **helm:** generic Helm chart for any Kubernetes cluster (Phase 4) (`d362538`)
  deploy/helm/certinel — one `helm install` stands up Certinel on any cluster.
  - Deployment (container-mode app + nginx sidecar serving the static frontend + an initContainer
    staging it from the image) + Service + Ingress.
  - TLS + CAC/client-cert terminated at the ingress (ingress-nginx auth-tls-* annotations forward
    the verified identity as X-Client-* headers the app reads).
  - DB: SQLite on a PVC (1 replica, Recreate) by default; `db.backend=postgres` (url or
    existingSecret) flips to replicaCount + RollingUpdate for HA.
  - CronJobs for the timer tasks (expiry-warn / auto-renew / deliver) via the image's `cron
    <task>` entrypoint, co-located with the app pod (shared RWO PVC).
  - Secret (license blob, OpenBao role_id/secret_id/CA, PG url) created only when set inline;
    supports referencing existing secrets. ServiceAccount, PVCs, values-driven
    resources/ingress/persistence. README + NOTES.
  Validated: `helm lint` clean; `helm template` renders correctly for sqlite, postgres+HA, and
  mtls/license/openbao; **server-side dry-run on a live K8s 1.30 cluster accepts all 10 objects.**

## 3.10.0 — 2026-06-22

_Released 2026-06-22. 1 change since v3.9.0._

### Features

- **image:** container image (UBI9 + slim) + CI publish on release (Phase 3) (`bf0ea17`)
  - Containerfile: one multi-stage build, two bases via PYBASE — UBI9/Python-3.12 (default,
    FIPS/gov) and python:3.12-slim. Bundles the venv (incl. psycopg so one image serves SQLite or
    Postgres), app + helper + frontend + VERSION, runs container-mode (CERTINEL_CONTAINER=1, no-
    sudo helper). entrypoint roles: web | migrate | cron <task>. Portable package step
    (dnf/microdnf/yum/apt).
  - .containerignore keeps the build context lean.
  - release job now builds + pushes both variants to the GitLab registry
    (registry.ac2solutions.com/ac2-solutions/certinel): :vX.Y.Z, :latest, :vX.Y.Z-slim, :slim —
    via rootless buildah on the shell runner. Non-fatal so an image hiccup never undoes a cut
    release.
  Validated on the runner: UBI9 image builds + `web` serves /api/health (version 3.9.0) with
  HELPER=[...] (no sudo); slim builds at ~175 MB; the gitlab-runner user builds rootless (subuid +
  job-local REGISTRY_AUTH_FILE).

## 3.9.0 — 2026-06-22

_Released 2026-06-22. 1 change since v3.8.0._

### Features

- **container:** container-mode backend (Phase 2) — no-sudo helper, ingress mTLS, entrypoint (`a6921e0`)
  Flag-gated by CERTINEL_CONTAINER (default off, so the VM/systemd path is unchanged):
  - the privileged helper is invoked directly (no `sudo -n`) — in a container the app + helper are
    the same user and the container is the privilege boundary. HELPER built via
    _helper_cmd(container_mode) so both paths are unit-tested.
  - mTLS: in container mode TLS + client-cert verification is terminated at the ingress (which
    passes the X-Client-* headers the app already reads), so the admin "set mtls mode" records the
    setting and returns mtls_managed_by=ingress instead of rewriting in-pod nginx via the helper.
  - container/entrypoint.sh: one image, role-selected — `web` (gunicorn on
    0.0.0.0:$CERTINEL_PORT), `migrate`, and `cron <expiry-warn|auto-renew|deliver>` for k8s
    CronJobs. Sets CERTINEL_CONTAINER=1 for everything it launches.
  Schema is created on import (init_db), so web/migrate both build it. SQLite suite 103 passed;
  container paths covered by test_helper_cmd_container_vs_vm and
  test_mtls_managed_by_ingress_in_container_mode.

## 3.8.0 — 2026-06-22

_Released 2026-06-22. 1 change since v3.7.0._

### Features

- **db:** SQLite<->Postgres migration tool + Admin Database page (Phase 1 finish) (`dfb88d6`)
  Completes the pluggable-DB phase with the migrate path the operator needs:
  - backend/db_migrate.py: copy_database() copies every table's rows between backends (schema has
    no FKs, so a straight table-by-table copy is safe); ON CONFLICT DO NOTHING for idempotency;
    advances Postgres IDENTITY sequences past copied ids. ensure_target_schema() builds the target
    via app.init_db().
  - tools/certinel-db-migrate: CLI — `certinel-db-migrate --to <pg-dsn>` migrates the current DB;
    --from/--check/--wipe-target. Installed to /usr/local/sbin.
  - Admin -> Database panel: shows the active backend + location, tests a target Postgres DSN, and
    renders the exact tailored switch steps (stop -> migrate -> set CSR_DB_URL -> start). Routes
    GET /api/admin/database + POST .../test.
  - Manifests (deploy.sh/verify.sh) + tests: sqlite->sqlite migrate round-trip and the admin
    status endpoint. SQLite suite 101 passed.
  Validated sqlite->Postgres on a real PG: rows copied + an insert after migration gets a fresh id
  (sequence reset works).

## 3.7.0 — 2026-06-22

_Released 2026-06-22. 4 changes since v3.6.0._

### Features

- **db:** pluggable database backend — SQLite (default) or PostgreSQL (`c9d1ea5`)
  Introduces backend/db.py, a thin abstraction so the app's ~354 sqlite3-style call sites run
  unchanged on PostgreSQL:
  - '?' -> '%s' (and '%' -> '%%') placeholder shim; PRAGMA no-ops on PG
  - hybrid Row (row["x"], row[0], dict(row)); rowcount on both
  - ddl() translates AUTOINCREMENT/REAL per dialect; table_columns() replaces PRAGMA table_info
    for the idempotent migrations; insert_returning_id() replaces cursor.lastrowid;
    dbx.IntegrityError catches on either backend
  - backend chosen by CSR_DB_URL / CSR_DB_BACKEND (default sqlite at CSR_DB_PATH)
  Wiring: init_db()/db()/import_certs/slack_listener route through db.connect(); the 2 INSERT OR
  IGNORE upserts -> portable ON CONFLICT DO NOTHING; 4 lastrowid -> insert_returning_id; 5 except
  sqlite3.IntegrityError -> dbx.IntegrityError.
  psycopg kept in a separate requirements-postgres.txt so the SQLite offline wheelhouse stays slim.
  CI gains a smoke-tests-postgres job (postgres:16 service) running the full suite against PG.
  SQLite smoke suite green (98/98), zero change in default behavior.

### Fixes & improvements

- **db:** postgres parity — nocase collation, test global reset, real-PG CI (`f892259`)
  Validated the whole smoke suite against a real PostgreSQL 13 and fixed the two issues it surfaced
  (both now 99/99 on PG, unchanged 99/99 on SQLite):
  - COLLATE NOCASE (9 query sites) has no Postgres collation -> db.prepare() creates a case-
    insensitive ICU `nocase` collation at init_db start so those ORDER BY / `= ? COLLATE NOCASE`
    queries resolve unchanged.
  - test_db_shim_logic leaked the dummy `_pg_dsn` (only reset _backend in finally), poisoning
    every later DB test's connection; reset all resolution globals.
  CI: smoke-tests-postgres now brings up an ephemeral user-local Postgres via initdb/pg_ctl on a
  unix socket (the shared runner is a shell executor without Docker `services:`), runs the full
  suite, and tears it down. Dropped allow_failure — it's a real gate now. (Runner needs postgresql-
  server, installed on ac2-git-runner.)

### Other changes

- detach ephemeral postgres stdio (-l) so the shell runner doesn't hang (`d7022db`)
- **db:** unit-gate the backend shim logic; mark PG service job allow_failure (`cacc92d`)

## 3.6.0 — 2026-06-22

_Released 2026-06-22. 1 change since v3.5.0._

### Features

- **guide:** per-field "?" help popovers + availability note (`eaaff40`)
  Every field in the setup guide now has a "?" button that opens a popup explaining exactly what the
  value is and how to obtain it — including the Vault commands for role_id (bao read .../role-id)
  and secret_id (bao write -f .../secret-id), how to find the PKI mount/role, what the FQDN must
  satisfy, etc. Plain-English, vendor-neutral.
  Also adds a note clarifying the guide opens standalone in any browser BEFORE install, and is
  linked in-app (Setup Guide) once installed.
  Self-contained popover (no deps); esprima-validated; all 12 "?" buttons map to a HELP entry.

## 3.5.0 — 2026-06-21

_Released 2026-06-21. 1 change since v3.4.0._

### Features

- **guide:** interactive start-to-finish setup runbook (`4b11a6a`)
  Adds frontend/setup-guide.html — a self-contained, dependency-free interactive guide written for a
  non-technical operator. The reader fills in their details (edition, hostname, sign-in method,
  OpenBao, org, email) and every step + copy- paste command live-tailors to match; blanks render
  highlighted placeholders.
  Covers the whole path: prerequisites → install (online + offline) → first admin bootstrap →
  license → org identity → sign-in (local/CAC + gov banner) → OpenBao auto-signing → email → first
  cert → verify, plus commercial/government extras, troubleshooting, and a glossary. Works offline
  and before the app is installed.
  - Linked in-app as "Setup Guide" in the header (opens /csr/setup-guide.html).
  - Added to deploy.sh manifest + verify.sh; README pointer.
  - Inline JS validated (esprima); all data-tpl bindings have matching cases.

## 3.4.0 — 2026-06-21

_Released 2026-06-21. 2 changes since v3.3.0._

### Features

- **sign:** per-user OpenBao audit attribution via on-behalf-of token (`612a1c0`)
  Each in-UI OpenBao sign now mints a short-lived child token stamped with the issuing user's
  identity (display_name + metadata.certinel_actor), so OpenBao's own audit log attributes the
  issuance to the individual rather than the shared AppRole — an independent, tamper-evident trail
  for audits.
  - sign.py: _obo_token() creates the child token from the AppRole token; sign_csr / _sign_openbao
    take an `actor`. Attribution never blocks issuance (falls back to the AppRole token on any
    failure).
  - actor threaded from all call sites: manual approve-&-sign (approver DN), auto-sign (auto-
    sign:<requester>), ACME server (acme-server), auto-renew.
  - Works for every Certinel auth mode (CAC + local) — no Keycloak dependency.
  - Requires the AppRole policy to allow auth/token/create (the default policy grants it unless
    token_no_default_policy is set).
  - tests: _obo_token stamps actor + fails safe; updated two ACME mocks for the new kwarg. Full
    smoke suite green (98).
- **licensing:** unlimited edition + per-edition domain quota (`bb0fe8b`)
  Adds the `unlimited` edition (Commercial capabilities, no domain cap) and enforces a registrable-
  domain cap on signing:
  - licensing.py: parse `max_domains` from the license payload (default by edition — commercial=1,
    others=0/unlimited); expose licensing.max_domains().
  - capabilities.py: `unlimited` grants the full Commercial capability set (no gov pack); EDITIONS
    updated.
  - domains.py (new): dependency-free eTLD+1 extraction + pure quota math.
  - sign.py: _enforce_domain_quota() gates every backend at sign_csr — the first domain claims the
    slot, renewals/re-issues of it stay free, a second distinct registrable domain is refused on
    Commercial. Licensed-domain set persists in app_settings (enforced fully offline). No-op when
    uncapped.
  - certinel-issue-license: `--edition unlimited` + `--max-domains N`; payload now carries
    max_domains (byte-compatible with the portal's Go signer).
  - deploy.sh / verify.sh: ship backend/domains.py.
  - tests: registrable-domain, quota math, unlimited capabilities, and a commercial 1-domain
    block/renew/upgrade flow. Full smoke suite green (97).
  Verified: licenses minted with the real vendor key (CLI tool) verify against the embedded pubkey
  with max_domains flowing through (unlimited→0, commercial --max-domains 3→3).

## 3.3.0 — 2026-06-21

_Released 2026-06-21. 1 change since v3.2.2._

### Features

- **licensing:** harden edition gating against trivial bypass (`fcbb0ff`)
  Closes the two env-var backdoors that unlocked paid editions with no forgery, and adds watermark /
  tamper-evidence / an optional host-binding tripwire so theft is at least loud and legally clean.
  Mechanism (build_mode.py): the insecure dev/eval overrides are honored ONLY in a development
  build. A release build — stamped on the installed copy by deploy.sh, or marked with
  CERTINEL_RELEASE=1 — ignores them, so the embedded vendor key is the only trust anchor and a valid
  signed license is the only way to unlock paid capabilities. The environment can only ever tighten
  a build (mark it release), never loosen it; loosening requires editing source, which is the
  irreducible floor for self-hosted.
  - build_mode.py: dev vs hardened-release distinction (new module)
  - licensing.py: CSR_LICENSE_PUBKEY trust-anchor swap gated to dev builds; optional bind_host
    soft tripwire surfaced in info().warnings
  - capabilities.py: CSR_ENTITLEMENTS=* grant-all gated to dev builds
  - app.py: startup banner — license watermark (licensed-to), loud UNLICENSED / DEV-OVERRIDE
    warnings, mirrored to the audit stream
  - routes_me.py + frontend: persistent edition/licensed-to header badge
  - certinel-issue-license: --bind-host
  - deploy.sh: stamp installed build_mode.py as a release build (CERTINEL_DEV_DEPLOY=1 keeps
    overrides on an eval box)
  - deploy.sh/verify.sh manifests: register build_mode.py
  - tests: release-build inertness + host-binding warning (93 pass)

## 3.2.2 — 2026-06-21

_Released 2026-06-21. 1 change since v3.2.1._

### Fixes & improvements

- **guide:** wizard uses the app's real theme variables (was unreadable) (`2672d79`)
  The connection wizard styled against CSS vars that don't exist (--card, --input) so the fallbacks
  rendered a white modal + white inputs while text stayed --fg (light) - light-on-white, unreadable
  on the dark theme. Re-style against the app's actual tokens (--modal-bg, --bg-input, --border-
  input, --fg-muted, --log-bg/--log-fg, --accent/--accent-fg) so it matches both light and dark
  themes, with focus states and clearer step separators.

## 3.2.1 — 2026-06-21

_Released 2026-06-21. 1 change since v3.2.0._

### Fixes & improvements

- **brand:** backup dir + offline placeholder use certinel, not csr (`ba0593d`)
  Rebrand remnants the rename missed (separate string literals, not the csr-dashboard slug):
  - certinel-backup wrote snapshots to /root/csr-backup-* -> /root/certinel-backup-*
  - offline bundle default hostname placeholder csr-host -> certinel-host
  - nginx fragment + runbook comments referencing csr-host
  Kept (the generic CSR = Certificate Signing Request acronym): the /csr/ URL, csr-subject / csr-
  info API endpoints, the csr-certs OpenBao delivery base path (changing it would break existing
  Vault policies), and CHANGELOG history.

## 3.2.0 — 2026-06-21

_Released 2026-06-21. 2 changes since v3.1.0._

### Features

- **guide:** interactive OpenBao/CyberArk connection setup wizard (`aceea01`)
  Adds an in-app wizard so admins don't have to reverse-engineer which knobs a secrets-manager
  connection needs. Pick an integration, fill in your values, and it generates tailored, copy-
  pasteable setup steps end to end:
  - OpenBao/Vault signing (PKI): enable engine, role, least-privilege policy, AppRole mint, the
    env vars, and the Admin -> Signing/CA fields
  - OpenBao cert delivery (KV v2): policy extension + per-template delivery config
  - OpenBao private-key storage (vault / return_once) policy + UI setting
  - CyberArk Conjur delivery: policy YAML, host API key, env + template config All values are
    generic placeholders - no environment specifics.
  Self-contained: appended to app.5-guide.js, injects its own modal + scoped styles + launcher (into
  the Signing/CA and Templates admin panels) via JS, so it touches no other file - deliberately
  avoids the files in open MR !84. Validated: esprima AST parse clean; served 200 on a live box.

### Other changes

- **fips:** accreditation checklist + correct RHEL 10 CMVP status (`844ed1b`)

## 3.1.0 — 2026-06-20

_Released 2026-06-20. 3 changes since v3.0.5._

### Features

- **ops:** runtime secret fetch from OpenBao/Vault (openbao-fetch) for alerts (`cfe9d6b`)
  Adds a reusable, dependency-free openbao-fetch (AppRole login -> read one KV-v2 field -> revoke
  token). The doctor-alert wrapper uses it when MAILGUN_OPENBAO_PATH is set, so the Mailgun key is
  read at runtime instead of baked into a config: rotating it is 'bao kv put secret/mailgun
  api_key=NEW' with no redeploy. A static MAILGUN_API_KEY still wins, so non-OpenBao installs are
  unaffected. Works against OpenBao or HashiCorp Vault (same API). AppRole creds live only in
  /etc/openbao/approle.env (0600); the secret itself never touches the box.
- **ops:** certinel-doctor.timer - scheduled health check + Mailgun email on failure (`58a3d84`)
  Runs certinel-doctor every ~15m (systemd timer). certinel-doctor-alert wraps it and, on FAIL,
  emails via Mailgun - state-based so it alerts on healthy->FAIL, re-sends every RENOTIFY_HOURS
  while down, and sends a RECOVERED notice. Config in /etc/certinel/doctor-alert.conf (Mailgun
  key/domain/recipient); with no creds the timer still runs + journals, so it's safe to enable by
  default.
  deploy.sh installs the units + alert tool, seeds a blank 0600 doctor-alert.conf, and enables
  certinel-doctor.timer alongside the others. verify.sh tracks them.
- **ops:** certinel-doctor health check + run it at end of install (`3fc6753`)
  Read-only health probe for a deployed host that actively tests the failure classes that bit
  installs this cycle, so problems surface immediately rather than at first login:
  - service active (decodes 203/EXEC and 200/CHDIR exit codes)
  - service account can traverse /opt/certinel + exec the venv (DAC)
  - SELinux exec label on gunicorn (flags the var_lib_t mislabel)
  - GET /csr/ 200 + /api/health version matches deployed VERSION
  - nginx -t, no duplicate server_name, static root present
  - auth_mode/mtls_mode sanity (flags the unlicensed mtls_mode=optional gate)
  - TLS expiry vs the step-ca auto-renew timer
  - data dir writable by the service account
  - no legacy csr-dashboard remnants Exit 1 on any FAIL. Installed as /usr/local/sbin/certinel-
    doctor; online-install runs it as a non-fatal post-install step. Complements verify.sh (file
    drift).

## 3.0.5 — 2026-06-20

_Released 2026-06-20. 1 change since v3.0.4._

### Fixes & improvements

- **deploy:** app dir must be group-traversable by the service account (`6b77a97`)
  /opt/certinel is the service WorkingDirectory, so the service account has to CHDIR into it. It was
  created root:root (and the installer listed it twice - the root:root 0755 entry shadowed the
  correct root:$SERVICE_GROUP one), so a deploy could leave it root:root 0750 -> gunicorn died with
  status=200/CHDIR 'Permission denied' and nginx 502'd (the UI then fell back to a CAC prompt).
  - deploy.sh: create /opt/certinel root:$SERVICE_GROUP 0750 (was root:root 0755)
  - online-install.sh: drop the duplicate root:root /opt/certinel dir entry

## 3.0.4 — 2026-06-20

_Released 2026-06-20. 1 change since v3.0.3._

### Fixes & improvements

- **install:** tolerate pasted text around the step-ca fingerprint (`6df2ebd`)
  The fingerprint prompt rejected anything that wasn't exactly 64 hex chars, so a paste that
  included surrounding text (e.g. '<fp> (full 64 chars)') or a 'sha256:' prefix failed. Extract the
  first 64-hex token from the input, then validate - the operator no longer has to strip annotations
  by hand.

## 3.0.3 — 2026-06-20

_Released 2026-06-20. 1 change since v3.0.2._

### Fixes & improvements

- **auth:** unlicensed boxes can save auth settings (mtls_mode gate) (`9b04e18`)
  Installs without a CAC license were seeded with mtls_mode=optional, so every Admin ->
  Authentication save (e.g. adding a trusted domain) echoed that value back and tripped the license
  gate -> 403 'CAC / mTLS is a licensed feature', even though mTLS was greyed out and untouched.
  - online-install.sh: when mTLS is disabled, seed mtls_mode=off and write 'ssl_verify_client off'
    (was 'optional' + optional_no_ca).
  - routes_auth.py: only 403 on an ACTIVE enable (a real change to optional/enforce). A save that
    merely re-sends a stale value is coerced to off so it lands - and self-heals boxes seeded
    optional by old installers.

## 3.0.2 — 2026-06-20

_Released 2026-06-20. 1 change since v3.0.1._

### Fixes & improvements

- **install:** auto-detect Python (el9 has no 3.12) + idempotent fapolicyd trust (`bf36f85`)
  Two install failures hit during the certinel rollout:
  - online-install.sh hardcoded PYBIN=python3.12, which does not exist on RHEL/Alma 9 (only
    python3.9) -> install died at the venv step. Detect the newest available python3.x instead of
    assuming 3.12.
  - deploy.sh used 'fapolicyd-cli --file update', which errors with '<path> is not in the trust
    database' on a fresh STIG box (the entry does not exist yet). Use 'add' first, fall back to
    'update' on re-deploy.

## 3.0.1 — 2026-06-20

_Released 2026-06-20. 1 change since v3.0.0._

### Fixes & improvements

- app dir SELinux label (203/EXEC) and /csr/ static root after rename (`f8759b6`)
  Two regressions surfaced by the csr-dashboard->certinel rename when the app moved into
  /opt/certinel:
  - deploy.sh labelled /opt/certinel as var_lib_t (a stale data-root rule). Harmless while the app
    lived at /opt/csr-dashboard, but once the venv moved into /opt/certinel, systemd could no
    longer exec gunicorn (status=203/EXEC, 'Permission denied'; runs fine via sudo -u, i.e. DAC ok
    / SELinux deny). Drop the bad rule, self-heal it on upgrade with 'semanage fcontext -d', and
    force-restorecon so the app dir returns to an exec-able type. Only the writable data root
    stays var_lib_t.
  - The static frontend is served by nginx 'location /csr/ { root /var/www; }' which resolves to
    /var/www/csr. The rename moved the docroot to /var/www/certinel, breaking /csr/ with 404.
    /var/www/csr is the CSR-acronym docroot coupled to the kept /csr/ URL (like 30-csr.conf), so
    revert it.
  Both verified live on the certinel VM: certinel-api active, /csr/ -> 200, /csr/api/me -> 200,
  first admin bootstrapped.

## 3.0.0 — 2026-06-20

_Released 2026-06-20. 4 changes since v2.32.0._

### Breaking changes

- rename csr-dashboard slug to certinel across all internal identifiers (`1acda00`)
  Full Tier-3 rebrand so a deployed system shows only Certinel naming — no legacy csr-dashboard
  remnants in services, accounts, or paths customers can see while it runs.
  Renamed: /opt/csr-dashboard   -> /opt/certinel /etc/csr-dashboard   -> /etc/certinel       (+
  certinel.env) /etc/pki/csr-dashboard -> /etc/pki/certinel /etc/nginx/csr-dashboard.d ->
  /etc/nginx/certinel.d /var/www/csr         -> /var/www/certinel service account csrapi -> certinel
  csr_dashboard_helper.sh + .d/ -> certinel_helper.sh + .d/ CSR_DASHBOARD_ENV    -> CERTINEL_ENV
  CSRF header value 'csr-dashboard' -> 'certinel' (frontend + backend) tools/csr-* + csrbackup.sh ->
  tools/certinel-*
  Kept the generic 'CSR' acronym (Certificate Signing Request), consistent with keeping the /csr/
  URL: the /csr/ path, CSR_* app env vars, csr_subject.py, and the nginx 30-csr.conf location
  fragment.
  deployments are handled by fresh reinstall (no in-place migration). CHANGELOG history and README
  'formerly' note left intact.

### Fixes & improvements

- rename csr-dashboard slug to certinel across all internal identifiers (`1acda00`)
  Full Tier-3 rebrand so a deployed system shows only Certinel naming — no legacy csr-dashboard
  remnants in services, accounts, or paths customers can see while it runs.
  Renamed: /opt/csr-dashboard   -> /opt/certinel /etc/csr-dashboard   -> /etc/certinel       (+
  certinel.env) /etc/pki/csr-dashboard -> /etc/pki/certinel /etc/nginx/csr-dashboard.d ->
  /etc/nginx/certinel.d /var/www/csr         -> /var/www/certinel service account csrapi -> certinel
  csr_dashboard_helper.sh + .d/ -> certinel_helper.sh + .d/ CSR_DASHBOARD_ENV    -> CERTINEL_ENV
  CSRF header value 'csr-dashboard' -> 'certinel' (frontend + backend) tools/csr-* + csrbackup.sh ->
  tools/certinel-*
  Kept the generic 'CSR' acronym (Certificate Signing Request), consistent with keeping the /csr/
  URL: the /csr/ path, CSR_* app env vars, csr_subject.py, and the nginx 30-csr.conf location
  fragment.
  deployments are handled by fresh reinstall (no in-place migration). CHANGELOG history and README
  'formerly' note left intact.

### Other changes

- finish Certinel rebrand of remaining visible CSR Dashboard text (`37de649`)
- **readme:** clone example uses the renamed certinel repo path (`8db2183`)
- **brand:** user-visible text -> Certinel; genericize DoD tooling language (`d75b6f7`)

## 2.32.0 — 2026-06-20

_Released 2026-06-20. 1 change since v2.31.1._

### Features

- **license:** gate CAC/mTLS behind Government licensing (Commercial add-on) (`095a684`)
  CAC / client-cert mTLS is now a licensed capability (auth.cac):
  - capabilities: auth.cac moves into the Government edition bundle; Commercial gets it via an
    explicit '--entitlements auth.cac' add-on (not in its base set).
  - backend: the auth-settings route refuses to enable it (auth_mode=mtls, or mtls_mode
    optional/enforce) without the entitlement -> 403. Turning it off needs no license.
  - installer: asks for the license first, then only offers the CAC/mTLS prompt when the license
    entitles it (cac_licensed via the stdlib licensing module). Unlicensed installs go local-only
    with a note that it can be enabled later in the UI after a license upgrade.
  - UI: Admin -> Authentication disables the CAC auth-mode option + the client-cert controls when
    unlicensed, explaining the requirement.
  Smoke test asserts the 403 gate (no entitlement) + acceptance with one.

## 2.31.1 — 2026-06-20

_Released 2026-06-20. 1 change since v2.31.0._

### Fixes & improvements

- **install:** seed auth_mode in the DB (not a dead env var) + first-admin OOBE (`f6e889e`)
  The installer wrote the auth choice to CSR_AUTH_MODE in the env file, but the app reads it from
  the app_settings 'auth_mode' row (auth_mode() = get_setting() or 'mtls'). So a fresh local-auth
  install came up in mTLS/CAC mode regardless of the choice. Also used AUTH_MODE=cac where the app
  stores 'mtls'.
  - AUTH_MODE is now 'mtls'|'local' (the app's values).
  - Seed app_settings auth_mode (+ mtls_mode/path) after deploy, then restart the service so it
    reads them. The dead CSR_AUTH_MODE env write is kept only as a record + clearly commented.
  - First-admin OOBE: enable CSR_BOOTSTRAP_FIRST_ADMIN (first authenticated user on an empty table
    becomes admin, self-disabling); local mode also opens self-registration so there's an account
    to bootstrap. Completion message is now mode-aware (the old ip:127.0.0.1 hint never worked in
    strict local mode).
  Live-applied + verified on the certinel box: auth_mode=local, registration_open.

## 2.31.0 — 2026-06-20

_Released 2026-06-20. 6 changes since v2.30.0._

### Features

- **auth:** app-managed nginx mTLS (client-cert) config in the admin UI (`5cafb43`)
  Makes the CAC/mTLS client-CA bundle a real, admin-configurable setting instead of an install-time-
  only nginx edit:
  - Helper 40-mtls.sh 'apply-mtls <off|optional|enforce> [bundle_path]' renders a dedicated
    /etc/nginx/csr-dashboard.d/10-mtls.conf fragment, nginx -t's it, and reloads - auto-reverting
    on a bad config so a wrong bundle can never down the site.
  - Admin -> Authentication gains a 'Client certificate (mTLS)' control (off / optional / required
    + bundle path); PUT /api/admin/auth-settings stores the choice and applies it via the helper
    (best-effort, reports mtls_applied).
  - Installer writes mTLS as that app-managed fragment (NOT baked into the server block, so no
    duplicate ssl_verify_client) and seeds mtls_mode/path into app_settings so the UI reflects the
    install choice.
  - Carries the earlier MR !71 fixes (DOD_CA_BUNDLE default + 64-hex fingerprint guard). New smoke
    test; helper part added to deploy/verify manifests.

### Fixes & improvements

- **systemd:** let the helper write /etc/nginx + /etc/pki/ca-trust (`acca0a3`)
  ProtectSystem=full makes /etc read-only for certinel-api and its sudo'd helper, so the new app-
  managed mTLS apply (writes /etc/nginx/csr-dashboard.d/10-mtls.conf) and the Trust store 'Install
  on this host' (writes /etc/pki/ca-trust anchors) failed with EROFS through the real sandboxed
  service. Add both dirs to ReadWritePaths; the rest of /etc stays read-only. Proven via a sandbox
  replica: without the carve-out the write fails 'Read-only file system'; with it, applied.
- **install:** default DOD_CA_BUNDLE + validate step-ca fingerprint (`0725870`)
  Two installer bugs hit during a live stepca/local-auth install:
  - DOD_CA_BUNDLE was only set when ENABLE_MTLS=yes, but the nginx server-block stanza references
    it in BOTH modes. Under `set -u` that aborted the install right after the cert was issued
    ('DOD_CA_BUNDLE: unbound variable'). Default it unconditionally before the auth prompt.
  - A step-ca root fingerprint pasted with an abbreviating ellipsis sailed through to `step ca
    bootstrap`, which then 404'd ('root ... not found'). Strip whitespace and require exactly 64
    hex chars, failing fast with a clear hint.

### Other changes

- **release:** RELEASING.md - notes file is transient, not committed (`9191e3f`)
- **release:** stop committing per-release notes; drop the 37 in-tree files (`ec82772`)
- Edit .gitignore (`9b57683`)

## 2.30.0 — 2026-06-20

_Released 2026-06-20. 1 change since v2.29.1._

### Features

- **install:** interactive installer + configurable service account (`015bfcb`)
  The online installer is now interactive: on a TTY it walks the operator through the environment-
  specific variables (service account, FQDN/URL, TLS source, auth mode, email, OpenBao, license)
  with sensible defaults, and confirms before acting. Every prompt is still overridable by an env
  var (+ ASSUME_DEFAULTS=yes) so unattended/CI installs keep working.
  Service account is now a first-class variable (default csrapi), threaded end to end:
  useradd/groupadd, directory + config + venv ownership, sudoers, and the systemd units'
  User=/Group= (deploy.sh renders the chosen account into the units and substitutes the manifest's
  :csrapi group). deploy.sh reads the choice from /etc/csr-dashboard/install.conf; with the csrapi
  default everything is byte-identical to before, so existing deployments are unaffected.
  TLS source is selectable: self-signed (default), bring-your-own (cert+key paths), or step-ca/ACME
  — the last bootstraps trust (--install), issues the leaf via a provisioner, and installs certinel-
  tls-renew.{service,timer} for daily auto-renewal (the 'proper auto-renew' path). bash -n gates the
  installer in CI.

## 2.29.1 — 2026-06-20

_Released 2026-06-20. 1 change since v2.29.0._

### Fixes & improvements

- **truststore:** make SSH push work under the certinel-api sandbox (`1c883f7`)
  Live-firing the trust-store SSH push from inside the certinel-api unit (ProtectHome=true,
  PrivateTmp=true) surfaced two bugs a plain shell hid:
  - push_ssh staged the bundle and installed it in two separate ssh calls using a $$-based remote
    temp path. $$ is the remote shell PID and differed between the two sessions, so the install
    couldn't stat the staged file. Collapse to a single ssh round trip: the bundle is piped on
    stdin and the remote shell mktemp's its own file, installs, and cleans up in one shell.
  - ProtectHome masks the service user's $HOME, so ssh couldn't persist known_hosts (noisy 'Could
    not stat ~/.ssh' + on a strict host a hard fail). Pin UserKnownHostsFile=/dev/null with
    accept-new. Apply the same to the deliver.py SSH provider, which shares the pattern.
  Proven: a real Vault-backed push from a systemd-run replica of the certinel-api sandbox now
  installs the CA into the target's trust (update-ca-trust extract).

## 2.29.0 — 2026-06-20

_Released 2026-06-20. 1 change since v2.28.1._

### Features

- **truststore:** in-app CA trust store with build + fleet distribution (`163babb`)
  Admins upload root/intermediate CAs in the UI (Admin -> Trust store), Certinel parses/validates
  them via the system openssl (FIPS-clean, no bundled crypto), assembles one CA bundle, and
  distributes it three ways so a whole fleet trusts the same CAs without anyone SSHing in to hand-
  edit anchors:
  - install on the Certinel host itself (helper install-ca-bundle subcommand -> update-ca-trust /
    update-ca-certificates, auto-detected)
  - push over SSH to fleet targets, reusing the delivery SSH credential convention (secret/csr-
    delivery-ssh/<host>) and running the host trust tool
  - a token-scoped pull endpoint + generated one-line install script for hosts the app can't reach
    (air-gapped / one-way firewall / SaaS)
  New: backend/truststore.py + routes_truststore.py, trust_certs/trust_targets/ trust_pulls tables,
  helper/csr_dashboard_helper.d/30-truststore.sh, Trust store admin panel, capabilities trust.store
  + trust.distribute.ssh (SSH push gated on a credential manager; pull + local install work
  everywhere). Bundle is public CA material (no private keys), so pull tokens are reusable within
  their TTL; expired tokens are GC'd by the certinel-deliver timer. 3 smoke tests; manifests
  updated.

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
