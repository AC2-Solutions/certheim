# Certinel v2 — In-UI Certificate Signing (OpenBao PKI)

Status: **delivered in v2.0.0.** (Original design + Phase 0 spike below, kept for
context.) Shipped: `sign.py` provider seam (OpenBao live, CyberArk slot),
approval-gated `POST /api/jobs/<id>/sign`, per-template policy + auto-sign,
revoke + CRL/OCSP, and the admin Signing/CA UI. See `RELEASE-NOTES-v2.0.0.md`.

## 1. Goal

Sign certificate requests **entirely in the dashboard UI**, replacing the
current out-of-band flow:

```
today:  requester → job 'pending' (CSR stored)
        → GitLab issue opened, assigned to a human signer
        → signer signs the CSR externally (with CA access)
        → signed cert uploaded back  →  _attach_signed_cert()  →  job 'issued'
```

v2 keeps the lifecycle but lets an **approver sign in the UI**, with the cert
produced by a CA backend instead of a human upload.

## 2. Decisions

- **CA backend:** OpenBao PKI secrets engine (already operated in the homelab;
  REST `sign` API, role-scoped policy + TTL caps, native audit, AppRole/JWT
  auth, HSM-capable).
- **Trust model:** **approval-gated** — a `_is_signer` approver triggers the
  sign; no blind auto-issue. (Per-template `auto_sign` is a later opt-in.)
- **Compatibility:** the manual / GitLab signer loop stays as the fallback for
  any template without an automated backend. Single mode *per template*, never
  two signing producers racing on one job.

## 3. Why it's a small change

The job model already does the hard parts:

- every `job` stores `csr_pem` (NOT NULL) and fills `cert_pem` on issue;
- `_attach_signed_cert()` is the **shared completion path** used by both manual
  upload and the GitLab inbound webhook, and it already runs
  `_verify_cert_matches_csr()` (CSR pubkey vs cert pubkey);
- `_is_signer(dn)` already models who may sign.

v2 adds an **automated producer** of the signed cert that feeds the same
`_attach_signed_cert()`. The lifecycle stays `pending → issued` (the approval is
the trigger); `error` on a sign failure.

## 4. Architecture

Mirror the `notify.py` provider pattern (already used for email:
`smg`/`smtp`/`mailgun` behind one dispatch).

### 4.1 New module: `backend/sign.py`
```
sign_csr(csr_pem: str, template: dict) -> SignResult(cert_pem, chain_pem)
```
Backends:
- `manual`  — the existing human/issue loop (default; `sign_csr` raises
  `BackendUnavailable` so callers fall back to the upload path).
- `openbao` — `POST <bao>/v1/<pki_mount>/sign/<role>` with `{csr, ttl, ...}`,
  returns `certificate` + `ca_chain`.

The backend interface is the seam for prod portability (§7).

### 4.2 Data model (additive migrations — same pattern as the v1.4.0
`first_name`/`last_name` add)

`cert_templates` gains:
| column | meaning |
|---|---|
| `signer_backend` | `manual` (default) \| `openbao` |
| `openbao_role`   | OpenBao PKI role name to sign against |
| `max_ttl`        | cap (seconds); app pre-check, OpenBao role is authoritative |
| `auto_sign`      | `0` default (approval required) \| `1` issue on request |

`jobs` gains (audit): `approved_by_dn`, `approved_at`, `signed_via`
(`manual`/`openbao`). `cert_pem` already exists for the result.

`app_settings` gains the connection config (non-secret): `openbao_addr`,
`openbao_pki_mount`, `openbao_auth_method`. **No OpenBao secret is stored in
`jobs.db`** — see §6.

### 4.3 New endpoint
```
POST /api/jobs/<id>/sign        @require_auth + _is_signer + @require_csrf
```
1. load job + its template; resolve `signer_backend`;
2. authorize the approver (`_is_signer`, and template/group scope);
3. policy pre-check (TTL ≤ `max_ttl`, SANs within allowed set);
4. `cert_pem, chain = sign.sign_csr(job.csr_pem, template)`;
5. `_attach_signed_cert(job, cert_pem)` (existing verify + 'issued' transition);
6. record `approved_by_dn/approved_at/signed_via`; `audit_log` the sign.

### 4.4 Admin / UI
- Admin **"Signing / CA"** tab (like the Email/GitLab tabs): OpenBao addr, PKI
  mount, default role, **Test connection** (`/sign` dry-run or `/issue` against
  a test role).
- Template editor: per-template `signer_backend` / `openbao_role` / `max_ttl` /
  `auto_sign`.
- Job view: pending jobs show **"Approve & sign"** (enabled only when the
  template has an automated backend); cert + chain download on issue.

## 5. Flow (approval-gated)

```
requester → POST /api/jobs            → job 'pending'  (csr_pem)
signer    → POST /api/jobs/<id>/sign  → policy check
                                       → OpenBao pki_csr/sign/<role>
                                       → _attach_signed_cert()  (verify pubkey)
                                       → job 'issued'   (or 'error')
```

## 6. OpenBao PKI setup (Phase 0)

A dedicated mount keeps blast radius small. The steps below are idempotent; run
them once against your OpenBao instance.

1. **Mount:** enable `pki_csr/` (separate from any existing PKI), set
   `max_lease_ttl`.
2. **Intermediate CA:**
   - *Spike:* `pki_csr/root/generate/internal` (self-contained internal root —
     proves the e2e mechanism).
   - *Production:* `pki_csr/intermediate/generate/internal` → sign the
     intermediate CSR with the **the internal root CA** (step-ca `ca.example.com`, or the
     offline the internal root CA key) → `pki_csr/intermediate/set-signed`, so issued certs
     chain to the already-trusted internal CA bundle. (Requires a CA-signing
     provisioner/key; tracked as Phase 0.5.)
3. **URLs:** set `pki_csr/config/urls` (issuing_certificates / crl_distribution
   / ocsp_servers) to the dashboard host so CRL/OCSP resolve.
4. **Role:** `pki_csr/roles/csr-dashboard` — `allowed_domains`,
   `allow_subdomains`, `server_flag`/`client_flag` (EKU), `key_usage`,
   `max_ttl`. **The role is the authoritative policy.**
5. **Scoped app credential:** an ACL policy that allows **only**
   `pki_csr/sign/csr-dashboard` (`update`) — no `issue`, no `root`/
   `intermediate`, no key read, no role write. Bind it to an **AppRole**
   (`role_id` + `secret_id`) or JWT (existing patterns:
   `openbao-gitlab-jwt`, `openbao-db-rotation-for-vm-services`). The app logs in
   to get a short-TTL token and signs; it can never mint a CA or read the key.

## 7. Security / STIG

- **CA key never on the app box** — it stays in OpenBao (HSM/PKCS#11-backable).
  The app holds only a narrowly-scoped credential to *request* a signature.
- **Approval-gated** — only `_is_signer` may trigger; every sign is written to
  `audit_log` (actor, job, role, serial).
- **Caps enforced twice** — TTL + allowed-domain/SAN/EKU in the OpenBao role
  (authoritative) and pre-checked in-app for a clean error.
- **New egress** — `gunicorn (csrapi) → OpenBao` over TLS is new outbound on the
  STIG box: allow it in firewalld and for the service account
  (`httpd_can_network_connect` is already on; the app→OpenBao path is separate
  from nginx). Pin the OpenBao CA in the app's trust.
- **Revocation** — OpenBao PKI gives `revoke` + CRL/OCSP nearly free; a v2.x
  "Revoke" action on issued jobs is a small follow-on.

## 8. Production portability

`sign.py`'s backend interface is the seam:

- homelab / enclave → `openbao` backend;
- an enterprise prod deployment → an enterprise sub-CA backend (EST/CMP) **or** the
  existing human loop. Auto-signing against the real DoD CA is normally
  policy-restricted (offline root, RA approval, HSM) — which is exactly why the
  default trust model is approval-gated.

No app-flow change between environments — only the backend + template policy.

## 9. Phasing

- **P0** — stand up `pki_csr` mount + role + scoped AppRole credential; prove a
  real (helper-generated) CSR signs end-to-end and the cert verifies against the
  chain.
- **P0.5** — replace the internal root with an internal-root-chained intermediate.
- **P1** — `sign.py` + `POST /api/jobs/<id>/sign` + template migrations + admin
  "Signing / CA" tab; approval-gated, reusing `_attach_signed_cert()`.
- **P2** — UI polish (Approve & sign, chain download), revoke + CRL/OCSP wiring,
  optional per-template `auto_sign`.

## 10. Open questions

- Where does the internal **root** sign the intermediate — a step-ca provisioner that
  permits CA certs, or the offline root key? (Blocks P0.5, not P0.)
- AppRole vs JWT for the app credential (lean AppRole: no per-request IdP
  dependency on the air-gapped box).
- Per-template `auto_sign` allowlist policy + who may set it (admin-only).
