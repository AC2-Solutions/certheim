# Certheim — Product Architecture Sketch

Status: **draft / north-star**. Not a commitment to dates or pricing; a frame so
feature work slots into a deliberate plan.

## 0. Framing decisions (agreed 2026-06-17)
- **Deployment-first:** self-hosted / on-prem (incl. **air-gapped**). Managed
  SaaS is a *later* mode, not the day-one center of gravity.
- **Primary market:** regulated & enterprise — gov/defense, finance, healthcare.
  Air-gapped/STIG is a **first-class, paid** deployment, not a niche.
- **Editions/licensing:** build a **license-agnostic capability layer now**;
  decide pricing/edition split later without rework.

These three imply a clear north star: **a self-contained, offline-capable,
audit-first product that a security team installs and runs themselves, where
every "connected" convenience is optional and degrades gracefully.**

---

## 1. Positioning (one line)
A self-hosted certificate **request → sign → lifecycle** dashboard for RHEL/PKI
fleets that runs the same whether you're cloud-connected or fully air-gapped —
CAC/mTLS or local auth, your CA, your chat tools, your audit trail.

## 2. Deployment modes (a customer is in exactly one)
| Mode | Connectivity | What's distinctive |
|---|---|---|
| **Air-gapped / high-side** | none | Offline bundle install (wheelhouse, no PyPI), STIG/FIPS/SELinux/fapolicyd, CAC mTLS, on-box/OpenBao CA, **no phone-home**, license verified **offline**. The reference build. |
| **On-prem connected** | egress only | Same product + the connected conveniences: Slack/Teams/Discord, Mailgun/SendGrid, SSO/OIDC, cloud/enterprise CA, update checks. Most enterprises. |
| **Managed SaaS** *(later)* | full | We host multi-tenant. Adds tenant isolation, hosted secrets, billing. Explicitly **phase 2** — do not let it distort the on-prem core. |

Design rule: **the air-gapped build is the floor.** If a feature can't work
offline, it's an *optional capability*, never part of the core path.

## 3. The capability model (the "feature-flag" architecture)
A feature is **available** only when all three layers agree:

```
available(feature) = entitled(feature)        # license/edition allows it
                   AND env_supports(feature)   # the environment can do it
                   AND admin_enabled(feature)  # an admin turned it on
```

**Layer A — Environment capabilities** (detected at install/boot, overridable):
`egress_internet`, `cac_pki`, `fips_mode`, `selinux_enforcing`, `fapolicyd`,
`smtp_relay`, `openbao`, `hsm`, … → what's *possible* here.

**Layer B — Entitlements** (license/edition): a signed, **offline-verifiable**
entitlements object listing licensed capability keys
(`integrations.chat`, `integrations.email_api`, `ca.openbao_signing`,
`auth.sso`, `airgap.bundle`, `audit.export`, `multi_instance`, …).
**License-agnostic now:** ship a default entitlements object that grants
everything; later a license file populates it. No online activation (air-gap).

**Layer C — Settings** (admin config, DB-backed): per-feature enable + config
(what we already do: `auth_mode`, `login_banner`, email method, integrations,
`slack_interactive_mode`, …).

The UI shows each feature as one of: **on** / **off (enable it)** /
**not licensed** / **unavailable in this environment** (with the reason). This
single model replaces ad-hoc `if get_setting(...)` checks scattered around.

## 4. One codebase, integrations behind flags
Today there's drift: the homelab feature line (auth/banner/email/integrations/
Slack — on `feat/configurable-login-banner`) vs the "production v1.4.0" tree.
**Converge to one tree.** Mechanics:
- A `capabilities.py` module = the resolver in §3 (env detect + entitlements +
  settings) with one `feature(key)` API the rest of the app calls.
- **Integrations are pluggable providers** behind interfaces (the pattern is
  already proven): `notify` (email: smg/smtp/mailgun/sendgrid/none),
  chat/webhooks (slack/teams/discord/generic, two Slack transports), and the v2
  `sign` providers (manual/openbao/…). New provider = drop-in, gated by a
  capability key.
- Optional runtime deps (e.g. `slack_sdk` for Socket Mode) become **declared
  optional extras**, present in the connected wheelhouse, absent (and cleanly
  inert) in the air-gapped one. No hand-installs.
- Optional services (e.g. `certheim-slack-listener`) ship in the systemd manifest +
  installer as **toggled components**, not manual scp.

## 5. Architecture pillars
- **Config & secrets:** declarative env + DB settings; secrets resolvable from a
  secret store (OpenBao/Vault) or files, never required in the DB. Per-instance.
- **Identity/auth:** one mode per instance (CAC/mTLS or local), pluggable; SSO/
  OIDC/SAML as a connected/enterprise capability. (Model A identity stays.)
- **CA / signing:** request→sign→issue lifecycle; signer providers (manual,
  OpenBao PKI, Windows AD CS standalone + **Enterprise template**, **ACME / RFC
  8555** — Let's Encrypt / step-ca / ZeroSSL / Sectigo / DigiCert, **EJBCA**,
  **Venafi**, **AWS Private CA**; CyberArk slot); approval-gated; key never on
  the app box. The ACME provider is a dependency-free client (openssl + stdlib
  JOSE) with pluggable challenge solvers (DNS-01 RFC2136/nsupdate +
  Cloudflare/Route53/Azure, HTTP-01 webroot). The dashboard also runs as an ACME
  *server* (RFC 8555) so certbot/cert-manager enroll from it directly, fronting
  the configured backend. This is the product's core differentiator — invest here.
- **Notifications & integrations:** email + chat + generic webhooks, all
  provider-pluggable and event-driven; rich messages (job deep-links, assign).
- **Audit & compliance:** append-only audit log + export; STIG/FIPS/SELinux/
  fapolicyd as first-class; reproducible offline bundle + checksums; SBOM.
- **Updates/packaging:** versioned **offline bundle** is the canonical artifact
  (already built); connected mode adds an *optional* update check. Signed
  releases. `deploy.sh`/installer remain the install spine.
- **No mandatory telemetry:** opt-in only; air-gap/gov require zero phone-home.

## 6. Onboarding / first-run
- **Installer** (offline + online) detects environment capabilities, walks a
  guided setup (domain/hostname, auth mode, **login banner**, email method,
  first admin/bootstrap), and writes config — most of this exists; make it the
  single front door and add the capability detection + (later) license import.
- **First-run admin** experience inside the UI: a setup checklist surfacing
  available-but-unconfigured capabilities (auth, CA signer, notifications,
  integrations) with the §3 status reasons.

## 7. Compliance posture (a feature, not overhead)
For the target market this is a selling point: STIG-hardened reference,
FIPS-validated crypto (stdlib PBKDF2/HMAC already), SELinux+fapolicyd-clean,
CAC/mTLS, full audit + export, air-gapped install, offline-verifiable license,
SBOM + signed artifacts, no outbound calls. Document it as a **compliance
matrix** customers can hand to their auditors.

## 8. Mapping what exists → the model
| Built (homelab line) | Capability key | Edition lean |
|---|---|---|
| Local + CAC/mTLS auth, login banner, agreement | `auth.local`,`auth.cac` | Core |
| Email: smg/smtp / none | `notify.email.smtp` | Core |
| Email: Mailgun/SendGrid | `notify.email.api` | Connected |
| Chat: Slack/Teams/Discord + generic webhooks | `integrations.chat` | Connected |
| Slack interactive assign (HTTP + Socket transports) | `integrations.slack.interactive` | Connected |
| v2 in-UI CA signing (OpenBao PKI, approval-gated) | `ca.signing.openbao` | Enterprise/Gov |
| Air-gapped offline bundle + STIG | `airgap.bundle`,`compliance.stig` | Enterprise/Gov |

## 9. Open decisions (deliberately deferred)
- Pricing & the exact edition split (flags make this late-bindable).
- License **enforcement** mechanism (signed offline license file + capability
  keys is the air-gap-friendly path; soft vs hard enforcement).
- SaaS timing & multi-tenancy design (phase 2).
- SSO/SAML, secret-store abstraction, SBOM tooling — scope when prioritized.

## 10. Suggested sequence
1. **Capability layer** (`capabilities.py`) + refactor existing `get_setting`
   gates to it (incl. a default "everything entitled" license object).
2. **Converge the branch** into one tree; mark integrations optional/flagged.
3. **Packaging pass:** optional extras (slack_sdk), installer toggles for the
   listener + integrations, compliance matrix doc.
4. Continue feature depth (v2 CA signing) — now slotting into the model.
