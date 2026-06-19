# Certinel — FIPS 140-3 Cryptography

## The claim, stated precisely

Certinel **bundles no cryptography of its own**. Every cryptographic operation it
performs is delegated to the **platform's cryptographic module**:

- the Python **standard library** (`hashlib`, `hmac`, `ssl`, `secrets`), which is
  linked against the system OpenSSL, and
- the system **`openssl`** binary (key/CSR generation, license-signature verify).

On a host booted in **FIPS mode** (RHEL 9 / Alma 9 with `fips=1`), that system
OpenSSL routes all crypto through the **FIPS 140-3 validated module** — the
*Red Hat Enterprise Linux 9 OpenSSL FIPS Provider* (OpenSSL 3.0.x FIPS provider,
CMVP-validated). So the accurate statement is:

> **When run on a FIPS-mode host, Certinel uses only FIPS 140-3 validated
> cryptography.**

It is *not* a claim that "Certinel" is itself a validated module — an application
cannot be 140-3 validated; the **module it calls** is. This is the same posture
HashiCorp/Red Hat/etc. products take.

## Why it's already compliant (no re-engineering)

| Operation | How Certinel does it | FIPS-approved? |
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

- **In Certinel's boundary:** everything above (its own hashing, HMAC, RNG, TLS,
  CSR/key generation, license verify).
- **Out of boundary (separate validation):** the **signing CA**. When signing via
  OpenBao/Vault, ACME, AD CS, EJBCA, Venafi, or AWS PCA, that backend performs the
  CA crypto and carries its **own** FIPS posture. Run a FIPS-validated CA backend
  for an end-to-end FIPS chain. Certinel only ever handles the CSR (public) and
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

Then in Certinel set **Require FIPS** (Admin → Signing/CA) so any drift is visible.

## RHEL major support — 140-2 vs 140-3

The FIPS *validation* is a property of the platform crypto module, not of
Certinel (which runs the same source on all three). One codebase serves them;
`fips_status().standard` reports which standard the host meets.

| RHEL | OpenSSL | FIPS standard | How Certinel detects it |
|---|---|---|---|
| **9** | 3.x (provider) | **140-3** — *RHEL 9 OpenSSL FIPS Provider* (`openssl-3.0.7-…el9_2`), covers 9.2/9.4/9.6 | FIPS **provider active** in `openssl list -providers` |
| **10** | 3.x (provider) | **140-3** — Red Hat **reuses the same** `3.0.7` validated provider; confirm RHEL 10 is a listed Operating Environment on the CMVP cert | same provider check |
| **8** | 1.1.1 (no providers) | **140-2** — RHEL 8 OpenSSL module | kernel FIPS flag + OpenSSL major `< 3` (no provider model exists) |

Notes:
- **Do not maintain a separate branch per RHEL.** The app code is identical; only
  the platform module (and its validation) differs. Detection is one function;
  build the offline bundle against the target's RHEL major (the wheelhouse/venv)
  and pin a release **tag** for an ATO.
- Target **RHEL 9 / 10 for a FIPS 140-3 claim**; RHEL 8 is **140-2** (and 140-2
  certificates are sunsetting to the CMVP Historical list).
- Always confirm the current certificate state on the
  [NIST CMVP list](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
  at deploy / accreditation time.

## Status across the reference deployment

- **disa (STIG/gov):** FIPS mode **enabled** — provider *Red Hat Enterprise
  Linux 9 - OpenSSL FIPS Provider 3.0.7*, active. Certinel there runs on the
  validated module today.
- **csr-dev (dev):** non-FIPS, by design.
