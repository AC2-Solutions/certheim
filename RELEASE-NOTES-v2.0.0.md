# CSR Dashboard v2.0.0

The dashboard moves from *tracking* certificate requests to *issuing* them.
A signer can now approve and sign a request entirely in the UI — the cert is
produced by a CA backend (OpenBao PKI) and flows through the exact same
verification and lifecycle as a hand-uploaded cert. The signing backend is
pluggable, the organization identity on every CSR is configurable, and the
codebase has been restructured for long-term maintainability.

## Highlights

- **In-UI signing, approval-gated.** A signer/admin clicks *Approve & sign* on a
  pending job; the cert is issued by the configured CA backend and verified
  (CSR↔cert pubkey) before the job flips to `issued`. The manual upload path
  remains as the fallback; both converge on one shared completion path.
- **Pluggable providers.** Signing is a provider registry — **OpenBao PKI**
  (fully implemented) and a **CyberArk** slot (configurable now, API wiring when
  an instance is available). The provider and its connection are chosen in the
  admin **Signing / CA** tab; the CA private key never resides on the app host
  (the app holds only a narrowly-scoped, env-only credential).
- **Per-template policy + auto-sign.** A certificate template can pin its own
  backend/role/TTL or inherit the global default, and can be set to issue
  automatically on request.
- **Revocation + CRL/OCSP.** Issued certs can be revoked from the UI; CRL/OCSP
  distribution points are surfaced.
- **Configurable organization identity.** The subject DN baked into every CSR
  (`C/ST/L/O/OUs/domain`) is no longer hardcoded. A first-run **CSR Subject**
  setup offers org profiles (DoD and its services, Federal Civilian, Commercial)
  and add/remove OU tags, with a live preview.
- **Deployment-flexible by design.** A capability/feature-flag layer makes every
  "connected" convenience optional and offline-verifiable (no phone-home); the
  air-gapped build remains the floor.

## Upgrading

- Schema changes are **additive and auto-migrated** on first start (no manual
  step). Existing deployments keep their current behavior until an admin opts in
  via the UI.
- **Set your organization identity:** after upgrading, an admin should open the
  **CSR Subject** tab and choose/confirm the org profile so new CSRs carry the
  correct subject (existing boxes fall back to their prior hardcoded defaults
  until configured).
- **To enable in-UI signing (optional):** configure a provider in **Signing /
  CA**, supply its credential in the service environment, and (for OpenBao) make
  the box able to reach the PKI endpoint. Until configured, signing stays manual.

## Security notes

- The CA signing key never touches the app host; the app uses a scoped
  credential that can only request a signature (and, where enabled, a revoke).
- The admin-configured CSR subject is written to a helper config that is
  **parsed, never sourced**, and sanitized on both sides — admin-supplied values
  are inert certificate fields, never executed.
- All entitlement checks are offline-verifiable with no external calls.
