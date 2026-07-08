# Certheim — FIPS 140-3 Cryptography

## The claim, stated precisely

Certheim **bundles no cryptography of its own**. Every cryptographic operation it
performs is delegated to the **platform's cryptographic module**:

- the Python **standard library** (`hashlib`, `hmac`, `ssl`, `secrets`), which is
  linked against the system OpenSSL, and
- the system **`openssl`** binary (key/CSR generation, license-signature verify).

On a host booted in **FIPS mode** (RHEL 9 / Alma 9 with `fips=1`), that system
OpenSSL routes all crypto through the **FIPS 140-3 validated module** — the
*Red Hat Enterprise Linux 9 OpenSSL FIPS Provider* (OpenSSL 3.0.x FIPS provider,
CMVP-validated). So the accurate statement is:

> **When run on a FIPS-mode host, Certheim uses only FIPS 140-3 validated
> cryptography.**

It is *not* a claim that "Certheim" is itself a validated module — an application
cannot be 140-3 validated; the **module it calls** is. This is the same posture
HashiCorp/Red Hat/etc. products take.

## Why it's already compliant (no re-engineering)

| Operation | How Certheim does it | FIPS-approved? |
|---|---|---|
| Password hashing | `hashlib.pbkdf2_hmac("sha256", …)` (PBKDF2-HMAC-SHA256) | **Yes.** Deliberately *not* werkzeug's default `scrypt`, which is **not** approved. |
| Webhook / token signatures | `hmac` + SHA-256 | Yes (HMAC-SHA-256) |
| Random (tokens, salts, pull tokens) | `secrets` / `os.urandom` → kernel DRBG | Yes |
| Key + CSR generation | system `openssl` (RSA-2048/3072/4096, ECDSA P-256/384) | Yes |
| License signature verify | `openssl dgst -sha256 -verify` (RSA + SHA-256) | Yes |
| TLS / mTLS (UI, webhook, k8s, OpenBao) | `ssl` + nginx, both system OpenSSL | Yes (FIPS ciphersuites only, enforced by the provider) |
| MD5 / SHA-1 in a security context | **none** | n/a |

No third-party crypto wheels are installed — `requirements.txt` is Flask + stdlib
only, so there is no pip-bundled OpenSSL/BoringSSL to slip outside the validated
module.

## What's in / out of the boundary

- **In Certheim's boundary:** everything above (its own hashing, HMAC, RNG, TLS,
  CSR/key generation, license verify).
- **Out of boundary (separate validation):** the **signing CA**. When signing via
  OpenBao/Vault, ACME, AD CS, EJBCA, Venafi, or AWS PCA, that backend performs the
  CA crypto and carries its **own** FIPS posture. Run a FIPS-validated CA backend
  for an end-to-end FIPS chain. Certheim only ever handles the CSR (public) and
  the returned certificate.
- Private keys generated server-side are written straight to the credential
  manager and shredded from the host (see `key-handling-design.md`); the brief
  generation itself uses the validated module.

## Self-check & enforcement (in the product)

- `capabilities.fips_status()` reports, at runtime:
  - `kernel_fips` — `/proc/sys/crypto/fips_enabled == 1`
  - `openssl_provider` — the **active** OpenSSL FIPS provider (name + version), or
    `null`. This is stronger than the kernel flag: it confirms the validated
    module is actually loaded and doing the work.
  - `validated` — both of the above true.
  - `required` / `compliant` — the admin `fips_required` policy and whether it's met.
- Surfaced in **Admin → Signing/CA** (and `GET /api/admin/capabilities` →
  `fips`). With **Require FIPS** on, the UI flags the deployment loudly when the
  validated module isn't active.

## Enabling & verifying FIPS

```bash
# enable FIPS mode (reboot required)
sudo fips-mode-setup --enable && sudo reboot
# verify after reboot
fips-mode-setup --check                 # "FIPS mode is enabled."
cat /proc/sys/crypto/fips_enabled       # 1
openssl list -providers | grep -A2 fips # name: ... OpenSSL FIPS Provider / status: active
```

Then in Certheim set **Require FIPS** (Admin → Signing/CA) so any drift is visible.

## RHEL major support — 140-2 vs 140-3

The FIPS *validation* is a property of the platform crypto module, not of
Certheim (which runs the same source on all three). One codebase serves them;
`fips_status().standard` reports which standard the host meets.

| RHEL | OpenSSL | FIPS standard | How Certheim detects it |
|---|---|---|---|
| **9** | 3.x (provider) | **140-3, validated** — *RHEL 9 OpenSSL FIPS Provider* (`openssl-3.0.7`), CMVP cert **#4857** (9.2–9.7; 9.0 is #4746) | FIPS **provider active** in `openssl list -providers` |
| **10** | 3.x (provider) | **140-3 NOT YET validated** — Red Hat *plans* to reuse the same `3.0.7` module, but RHEL 10 is **"Pending Operational Environment update"** on the CMVP list with **no cert number assigned** (as of 2026-06). Do **not** claim 140-3 on a 10 host until the OE is certified. | same provider check |
| **8** | 1.1.1 (no providers) | **140-2** — RHEL 8 OpenSSL module | kernel FIPS flag + OpenSSL major `< 3` (no provider model exists) |

Notes:
- **Do not maintain a separate branch per RHEL.** The app code is identical; only
  the platform module (and its validation) differs. Detection is one function;
  build the offline bundle against the target's RHEL major (the wheelhouse/venv)
  and pin a release **tag** for an ATO.
- Target **RHEL/Alma 9 for a FIPS 140-3 claim today** (CMVP #4857). **RHEL/Alma 10
  is not yet validated** — Red Hat's RHEL 10 OE certification is still pending, so
  treat 10 as FIPS-*capable* but not FIPS-*validated* until a cert number lands.
  RHEL 8 is **140-2** (and 140-2 certificates are sunsetting to the CMVP Historical
  list).
- Always confirm the current certificate state on the
  [NIST CMVP list](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
  at deploy / accreditation time.

## Status across the reference deployment

- **disa (STIG/gov):** FIPS mode **enabled** — provider *Red Hat Enterprise
  Linux 9 - OpenSSL FIPS Provider 3.0.7*, active. Certheim there runs on the
  validated module today.
- **csr-dev (dev):** non-FIPS, by design.

## Accreditation checklist (per deployment / ATO)

The product side of FIPS is done — the items below are **verification and process
steps an accreditor (ISSO/ISSM) performs at deployment time**, not code changes.
Walk this list once per accredited install and attach the evidence to the SSP.

- [ ] **Confirm the platform module on the CMVP list.** Look up the host's exact
      OpenSSL FIPS provider on the
      [NIST CMVP validated-modules list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)
      and confirm the host's **Operating Environment** (RHEL/Alma + version) is an
      explicitly listed OE on that certificate. Record the **certificate number**.
  - **RHEL/Alma 9** → *Red Hat Enterprise Linux 9 OpenSSL FIPS Provider* (OpenSSL
    `3.0.7`), 140-**3**, active, **CMVP cert #4857** (9.2–9.7; 9.0 is #4746).
    Confirmed in the reference deployment.
  - **RHEL/Alma 10** → **NOT yet validated (confirmed 2026-06).** Red Hat lists the
    RHEL 10 OpenSSL provider as *"Pending Operational Environment update"* with **no
    CMVP cert number**. The module is the same `3.0.7`, but the **OE certification is
    outstanding** — so 10 is FIPS-*capable*, not FIPS-*validated*. **Do not assert
    140-3 on a 10 host until a cert number lands.** The Certheim reference VM is
    Alma 10 → today, make the validated claim only on a 9 host, and re-check the
    [CMVP list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)
    for RHEL 10 before each accreditation.
  - **RHEL/Alma 8** → 140-**2** (OpenSSL 1.1.1, no provider model). **140-2 certs
    are moving to the CMVP Historical list**; treat RHEL 8 as legacy. Market guidance:
    *"FIPS 140-3 requires RHEL/Alma 9 or 10; RHEL 8 is 140-2 (sunsetting)."*
- [ ] **Boot the host in FIPS mode and prove it.** `fips-mode-setup --check` →
      enabled; `cat /proc/sys/crypto/fips_enabled` → `1`;
      `openssl list -providers` shows the FIPS provider **status: active**. Capture
      the output as evidence.
- [ ] **Prove the running app sees it.** `GET /api/admin/capabilities` → `fips`
      shows `kernel_fips: true`, `openssl_provider` populated (name + version),
      `validated: true`. The active-provider check is stronger than the kernel flag.
- [ ] **Turn on the policy.** Set **Require FIPS** (Admin → Signing/CA) so any
      drift (kernel off, provider not loaded) is surfaced loudly in the UI.
- [ ] **Pin the release for the ATO.** Record the deployed Certheim **git tag** and
      build the **offline wheelhouse/venv against the target host's RHEL major** so
      the accredited artifact is reproducible. (App source is identical across RHEL
      majors; only the platform module — and its validation — differs.)
- [ ] **Account for the CA backend separately.** The signing CA is **out of
      Certheim's boundary**. If an end-to-end FIPS chain is required, confirm the CA
      backend (OpenBao/Vault, AD CS, EJBCA, Venafi, AWS PCA, ACME server) carries
      its **own** FIPS validation and document it alongside Certheim's.
- [ ] **No third-party crypto crept in.** Confirm `requirements.txt` is still
      Flask + stdlib only (no pip-shipped OpenSSL/BoringSSL wheel that would run
      outside the validated module). Re-check after any dependency bump.

> **One-line claim to put in front of an accreditor:** *"On a FIPS-mode RHEL/Alma 9
> or 10 host, Certheim performs all cryptography through the platform's CMVP-validated
> OpenSSL FIPS provider (cert #__); Certheim bundles no cryptography of its own and
> enforces the posture at runtime via the Require-FIPS policy."*
