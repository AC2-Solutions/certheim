# C3 — Governance core: RBAC, multi-tenancy, SSO, SCIM

Design for Phase C3 of the Commercial roadmap. Where C1/C2 gave visibility and
outage prevention, C3 makes Certinel safe to hand to many teams: real roles,
tenant isolation, enterprise sign-on, and automated provisioning.

This is the most cross-cutting phase — it touches authorization app-wide — so it
ships as **additive, backward-compatible increments** that never weaken the
existing model until the new one is proven.

## Where we start (today's model)

- `users.is_admin` is a **binary** flag; `require_admin` / `require_auth` are the
  only gates. Everyone non-admin is an undifferentiated "user".
- `groups` + `user_groups` already exist (with a `role` column = `member`),
  used for job assignment and notification routing — a natural seed for teams.
- Identity arrives as `g.identity` (dn/cn/email), from local or CAC/mTLS auth.

## Increment C3.1 — RBAC core (roles + permissions) *(this increment)*

A permission layer that **supersets** the binary admin flag without breaking it.

- **`permissions.py`**: a fixed permission vocabulary (e.g. `inventory.view`,
  `inventory.manage`, `cert.request`, `cert.issue`, `cert.revoke`, `template.manage`,
  `user.manage`, `audit.view`, `settings.manage`) and a **role → permissions** map:
  - `admin` — everything (== today's `is_admin`),
  - `operator` — issue/manage/renew/deliver certs + inventory view,
  - `auditor` — read-only: inventory, audit log, reports,
  - `member` — request certs, see their own.
  `has_perm(identity, perm)` and a `require_perm(perm)` decorator; `is_admin`
  users implicitly hold every permission, so **nothing regresses**.
- **`users.role`** column (idempotent migration; default derived from `is_admin`:
  admin→`admin`, else `member`). Role assignment API + the Users admin panel.
- **Capability `governance.rbac`** (Commercial): when unlicensed, enforcement
  falls back to the binary admin check (base behavior); when licensed, roles are
  honored. Wiring is rolled out endpoint-by-endpoint, starting with the inventory
  reads (so `auditor`/`operator` — not just admin — can use the inventory).
- Tests: the role→permission resolution (pure).

## Increment C3.2 — Multi-tenancy (teams / business units)

- Promote `groups` into **tenants/teams** with their own membership and a
  **team-scoped role** (owner/operator/member), reusing `user_groups.role`.
- **Resource scoping**: tag certs/jobs/templates with an owning team; list/detail
  endpoints filter to the caller's teams (admins see all). A **delegated
  team-admin** manages members + assignments within their team only.
- Inventory ownership (C2.1) gains a team dimension, so alerts/digests route by
  team as well as individual owner.
- Open design decision (flagged for sign-off): **soft scoping** (one DB, rows
  tagged + filtered) vs **hard isolation** (separate schemas/instances). Default
  recommendation: soft scoping — simpler, fits the single-appliance model, and
  enough for business-unit separation; hard isolation only if a customer needs a
  compliance boundary.

## Increment C3.3 — Enterprise SSO (SAML + OIDC)

- **OIDC** first (Authorization Code + PKCE) — Certinel already lives behind
  Keycloak/OIDC in places, so the auth code is partly proven; then **SAML 2.0**
  for the enterprises that require it.
- **Claim → role/team mapping**: admin-configured rules map IdP groups/claims to
  Certinel roles and teams, so access is governed centrally.
- Coexists with local + CAC auth (auth method stays per-deployment); SSO is one
  more `auth_mode`.
- Open decision: dependency posture — a dependency-free SAML/OIDC implementation
  (consistent with the rest of Certinel) vs a vetted library. Lean dependency-free
  for OIDC (JOSE we already do for ACME); reconsider for SAML's XML-dsig.

## Increment C3.4 — SCIM provisioning

- A **SCIM 2.0** endpoint (`/scim/v2/Users`, `/Groups`) so an IdP (Okta/Entra/etc.)
  can create/deactivate users and sync group membership automatically — closing
  the joiner/mover/leaver loop instead of manual user admin.
- Bearer-token auth for the SCIM client; maps SCIM groups → Certinel teams/roles
  using the same mapping rules as C3.3.

## Packaging (every increment)

- Premium under `governance.rbac` (and `governance.sso` / `governance.scim` for
  C3.3/C3.4); base builds keep the binary-admin model.
- Idempotent migrations, tier-marked tests, deploy/verify manifest entries,
  admin UI, bottom-up propagation Commercial → Government. Government layers
  **separation-of-duties / dual-control (G2)** on top of this RBAC core.

## Backward-compatibility contract

At every step: an unlicensed or not-yet-migrated deployment behaves exactly as
today (admin vs non-admin). New roles only ever **grant** access that the binary
model would have required admin for — they never remove an admin's authority.
