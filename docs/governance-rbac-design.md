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

## Increment C3.2 — Multi-tenancy (HARD isolation) — DECISION: hard isolation

**Decided (2026-06-24):** tenants get a **real data boundary**, not soft
row-tagging — compliance-grade separation where one tenant's data is physically
unreachable from another's.

Architecture (works on both DB backends via the single `db.connect()` chokepoint):
- **Postgres**: one **schema per tenant** (`tenant_<slug>`); each request sets
  `search_path` to the resolved tenant's schema. Global rows (the tenant
  registry, license) live in a control schema.
- **SQLite**: one **database file per tenant**
  (`/var/opt/certinel/tenants/<slug>.db`); `connect()` opens the resolved
  tenant's file. The control DB holds the registry.
- **Tenant registry** (control plane): `tenants(id, slug, name, store, active,
  created_at)`; `users.tenant_id` binds a user to a tenant. A small `tenancy.py`
  resolves the **current tenant** from the authenticated user per request and
  hands `db.connect()` the right schema/file. Provisioning a tenant runs the full
  `init_schema()` against its new schema/file.
- **Backward compatible**: an unlicensed or un-provisioned deployment runs as a
  single implicit `default` tenant — `connect()` behaves exactly as today. Hard
  isolation only engages once `governance.multitenancy` is licensed and tenants
  exist.
- Delegated **team-admin** manages members within their tenant; cross-tenant
  visibility is reserved for the instance admin.

Rollout: (1) tenant registry + per-request resolution + a `default` tenant that
is a no-op [foundation, this increment]; (2) route `db.connect()` by tenant
(schema/file) + provisioning that runs init_schema; (3) admin UI + user→tenant
binding; (4) per-tenant background passes (alerts/renew/deliver iterate tenants).

## Increment C3.3 — Enterprise SSO (SAML + OIDC) — DECISION: vetted library

**Decided (2026-06-24):** use a **maintained SAML/OIDC library** rather than
hand-rolling — full SAML 2.0 + OIDC coverage, and the XML-dsig path stays in
audited code instead of bespoke crypto.

- Candidate: `python3-saml` (OneLogin) + an OIDC client (`authlib`/`oidclib`),
  pinned and **vendored into the offline bundle** so the air-gapped install still
  has zero network dependency at deploy time (the dependency is in the artifact,
  not fetched). Vetting note: review the lib's own deps for the air-gapped SBOM.
- **Claim → role/tenant mapping**: admin-configured rules map IdP groups/claims to
  Certinel roles (C3.1) and tenants (C3.2), so access is governed centrally.
- Coexists with local + CAC auth; SSO is one more `auth_mode`.
- Open sub-item to confirm at build time: exact library + version, and that its
  transitive deps are acceptable for the regulated/air-gapped SBOM.

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
