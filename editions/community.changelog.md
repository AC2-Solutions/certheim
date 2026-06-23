# Certinel Community edition — changelog

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

