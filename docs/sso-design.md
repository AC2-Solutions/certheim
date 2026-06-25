# C3.3 — Enterprise SSO (OIDC + SAML)

Design for Phase C3.3. Lets an enterprise IdP (Keycloak, Entra ID, Okta, Ping…)
be the login authority for Certinel, mapping IdP identity to Certinel's roles
(C3.1) and tenants (C3.2). Coexists with the existing local + CAC/mTLS auth — SSO
is one more `auth_mode`.

## Dependency decision (refined)

The earlier call was "use a vetted library rather than hand-roll." Reviewing the
codebase refines it by protocol:

- **OIDC → dependency-free.** Certinel already verifies RS256/ES256 **JWS** for
  the ACME server (`acme_server.jwk_to_pem()` + `openssl dgst -verify`), and does
  HTTP with the stdlib. OIDC is exactly that: discovery + an HTTP token exchange +
  an ID-token JWS verified against the IdP's JWKS. So OIDC reuses what's here — no
  `authlib`, no `cryptography` wheel — keeping the air-gapped/no-crypto-lib
  posture the rest of Certinel is built on.
- **SAML → vetted library.** XML-dsig (canonicalization + enveloped signatures)
  is genuinely risky to hand-roll; this is the part the "vetted library" decision
  was really about. Use **python3-saml** (OneLogin) → depends on **xmlsec** +
  **lxml**, which need the **libxmlsec1** system library. For an air-gapped RHEL
  install that means an RPM dependency (libxmlsec1, in EPEL) plus the wheels in
  the offline bundle — a real packaging cost to confirm before the SAML increment.

## Increment C3.3a — OIDC (this phase's first increment)

`sso_oidc.py`, dependency-free, Authorization Code + PKCE:

1. **Discovery**: fetch `<issuer>/.well-known/openid-configuration` (cached) for
   the authorization, token, and JWKS endpoints.
2. **Login** (`GET /api/auth/sso/login`): generate `state`, `nonce`, and a PKCE
   `code_verifier`/`challenge`; stash them server-side (short-TTL, like the local
   session store); redirect to the IdP authorize endpoint.
3. **Callback** (`GET /api/auth/sso/callback`): validate `state`; exchange `code`
   + `code_verifier` at the token endpoint; **verify the ID token** — signature
   (JWS via `jwk_to_pem` against the JWKS, kid-matched), `iss`, `aud` (==
   client_id), `exp`/`iat` skew, and `nonce`. Reject on any failure (this is the
   security boundary).
4. **Map → identity**: derive the Certinel user from configured claims
   (`username` ← `preferred_username`/`email`, plus `email`, display name), then
   map IdP group/role claims → Certinel **role** (C3.1) and **tenant** (C3.2) via
   admin-defined rules. Upsert the user and mint a **local session** (reusing the
   existing `local_sessions` flow), so the rest of the app is unchanged.

- **Config** (admin UI): issuer URL, client_id, client_secret, scopes
  (`openid profile email` + groups), and the claim-mapping rules. Stored in
  `app_settings` (shared/control — so it's instance-global, consistent with the
  license).
- **auth_mode**: add `"sso"`; `resolve_identity()` accepts a valid SSO session
  the same way it accepts a local one. Local/CAC remain available per the
  deployment.
- **Capability** `governance.sso` (Commercial; `egress_internet` is **not**
  required — the IdP is typically internal/reachable; we don't probe the public
  internet).
- Tests: PKCE/state/nonce generation, claim→role/tenant mapping, and ID-token
  validation (happy path + tampered sig / wrong aud / expired / bad nonce) using
  a locally-minted test key — all pure/offline.
- **Live verification**: end-to-end against the homelab **Keycloak** (real
  discovery, real code exchange, real ID-token) before it's trusted — the same
  "prove it live" gate used for tenancy.

## Increment C3.3b — SAML 2.0 (separate increment)

`sso_saml.py` on **python3-saml**: SP metadata, AuthnRequest, ACS endpoint with
signature + condition validation, attribute → role/tenant mapping reusing C3.3a's
mapper. Gated `governance.sso`. **Blocked on confirming the packaging**: the
libxmlsec1 RPM dependency for the air-gapped bundle + the transitive-dep SBOM
review. Do this after OIDC is live.

## Security notes

- All validation failures **fail closed** (no session minted). The ID-token
  checks (sig, iss, aud, exp, nonce) are the trust boundary and are unit-tested
  against tampered inputs.
- `state` + PKCE defend the callback against CSRF/code-injection; `nonce` binds
  the ID token to this login.
- Client secret + signing material live in `app_settings` (control plane), never
  in a tenant schema.
