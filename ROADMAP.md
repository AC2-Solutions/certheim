# Certinel Roadmap

Forward-looking plan for the paid editions. Certinel ships as three stacked
editions — **Community → Commercial → Government** — and this roadmap is delivered
edition-by-edition: Commercial first, then Government (which reuses the Commercial
foundations). Each item below lands as a licensed capability gated by build tier +
license entitlement, with tier-marked tests, deploy/verify manifest entries, admin
UI surfacing, and docs.

Status legend: ☐ planned · ◐ in progress · ☑ shipped

---

## Commercial

Goal: move from "issue and deliver certs" to a full certificate-lifecycle
platform — visibility, governance, and ecosystem integration.

### Phase C1 — Visibility foundation ◐
The inventory spine every later phase reads from.
- ☐ Unified certificate inventory — one model over issued (`jobs`), discovered
  (`fleet_certs`), and ACME-server (`acme_certs`) certs, with a source-adapter
  interface the discovery add-on plugs into.
- ☐ Risk intelligence — flags (expiry, weak key, SHA-1, self-signed, broken
  chain, over-long validity) plus a composite risk score.
- ☐ Inventory UI (filter/search/group) + inventory REST API.

### Phase C2 — Outage prevention
- ☐ Tiered alerting + escalation with owner assignment and SLA-breach tracking.
- ☐ Scheduled expiry digests per team/owner over existing email/chat channels.
- ☐ CT-log / shadow-cert monitoring (certs issued on your domains you didn't request).

### Phase C3 — Governance core
- ☐ RBAC + multi-tenancy — teams / business units, fine-grained roles, delegated
  admin, tenant isolation.
- ☐ Enterprise SSO (SAML + OIDC) and SCIM user/group provisioning.

### Phase C4 — Policy & self-service
- ☐ Policy engine — issuance guardrails (allowed CAs, key types/sizes, validity
  caps, SAN/CN constraints) enforced at request time.
- ☐ Self-service portal for app teams, bounded by RBAC + policy.

### Phase C5 — Endpoint push automation
- ☐ Push agent + targets: F5 / NetScaler / A10 load balancers, IIS / Windows cert
  store, nginx / Apache — wired into the auto-renew loop.

### Phase C6 — Ecosystem integrations
- ☐ ServiceNow, Terraform provider, Ansible module, CI plugins, cert-manager (k8s) issuer.
- ☐ SIEM/observability — syslog/CEF → Splunk/Sentinel, Prometheus metrics, audit export.

### Phase C7 — Crypto & hardware
- ☐ HSM-backed keys (PKCS#11) — Luna / nCipher / CloudHSM / Azure Managed HSM.
- ☐ Crypto-agility / PQC readiness — Crypto Bill of Materials (CBOM), algorithm
  inventory, migration tooling.
- ☐ SSH certificate management — SSH CA + key inventory.

---

## Government

Goal: meet public-sector assurance, federal PKI, and crypto-mandate requirements,
building on the Commercial foundations (RBAC → separation of duties, audit → WORM,
PKCS#11 → FIPS L3, CBOM → CNSA).

### Phase G1 — Assurance foundation
- ☐ HSM FIPS 140-3 Level 3 validated config + key-ceremony workflow.
- ☐ Tamper-evident / WORM audit logging with long retention (NIST AU controls).

### Phase G2 — Access & control
- ☐ Enforced separation of duties / dual control for issuance and revocation.

### Phase G3 — Federal PKI integration
- ☐ FPKI / Federal Bridge cross-certification, DoD CA chains, ECA.
- ☐ PIV-I and derived credentials (mobile), extending CAC/mTLS.

### Phase G4 — Compliance artifacts
- ☐ NIST 800-53 / RMF control mapping + eMASS / SSP evidence export.
- ☐ STIG / SCAP self-assessment content shipped with the appliance.

### Phase G5 — Crypto mandate
- ☐ CNSA 2.0 alignment + PQC migration tooling and reporting.

### Phase G6 — Air-gap & cross-domain
- ☐ Offline OCSP / CRL distribution and cross-domain transfer-friendly bundles.

---

## Sequencing notes

- C1 → C2 are serial (visibility before alerting). C3 can run alongside C2.
- C5 and C6 are connector fan-outs that parallelize with C3/C4.
- C7 closes Commercial and seeds Government (HSM, CBOM).
- On the Gov side, G1/G2/G4 largely parallelize once their Commercial
  dependencies land.

Per-feature design docs live under `docs/` (e.g. `docs/visibility-inventory-design.md`
for C1).
