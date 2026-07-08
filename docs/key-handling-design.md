# Certheim — Private-Key Handling (design)

## Principle

Certheim should hold a private key for the **minimum time, in the minimum number
of places**. The default is to **never persist a server-generated key on the
host**; when a server-side key must outlive the request, the **credential
manager (OpenBao / CyberArk) is the system of record — not the host
filesystem**.

This is configurable: one codebase, the admin picks the posture that fits the
deployment (SaaS, on-prem, air-gapped).

## The hierarchy (best → worst)

1. **Key never reaches Certheim** — the destination generates its own keypair
   and submits only a CSR, or uses ACME (cert-manager / certbot hold the key).
   Certheim is a pure signing/registration authority over *public* material.
   Already supported: external CSR upload + the built-in ACME server.
2. **Certheim generates, key never at rest on host** — born in `tmpfs`, pushed
   straight to the credential manager (or returned to the requester once), host
   working copy shredded.
3. **(legacy)** key generated to the host keystore (`/root/sslcerts/private`)
   and left at rest. Convenient, but a standing liability (host compromise,
   backups, disk forensics — what STIG/gov reviewers flag). Today's behavior.

## Admin-configurable policy

New setting **`key_storage`** (global default, optional per-template override),
surfaced in Admin → Signing/Security:

| value | meaning |
|---|---|
| **`vault`** *(default)* | Server-generated key is written to the credential manager (OpenBao KV today; CyberArk via the existing provider) as the durable store; the host copy is shredded. Nothing at rest on the host. |
| **`return_once`** | Key is handed to the requester exactly once (issuance response or a single-use pull token) and never persisted server-side. Best for ephemeral / short-lived; if missed, re-issue. |
| **`host`** | Legacy: keep the key in the host keystore for later UI download. Off by default; for air-gapped / no-vault deployments. |

**Generation always happens in `PrivateTmp`/`tmpfs`** regardless of policy — the
policy only decides where the key goes next and whether the host copy survives.

`key_storage` is orthogonal to the existing delivery **`key_mode`**
(`destination` / `ship` / `vault`): `key_storage` governs the key's **durable
home**, `key_mode` governs **pushing it to the destination**. (UI will explain
the pairing; `key_mode=vault` implies `key_storage=vault`.)

## Two things that currently want a host key — and their answers

- **One-time UI download** → hand the key to the requester at issuance (or via a
  single-use pull token); never store it. Missed → re-issue.
- **Delivery retry** (the `csr-deliver` timer is a fresh process) → write the key
  to the vault as the **first** step of issuance, so it's durable there
  immediately and the host copy drops; retries re-read from the vault.

## Short-lived certs: re-issue, don't retain

When validity ≤ a threshold, prefer **re-issue over retain/retry**: if the vault
write fails, re-mint rather than holding the key around. A 30-minute cert isn't
worth a persisted key — and this removes the "hold the key across retries"
problem entirely.

## OpenBao side

- Durable keys land at a KV path, e.g. `secret/certinel-keys/<host>` (or folded
  into the existing delivery bundle at `secret/csr-certs/<host>`).
- The `csr-delivery` policy (Ansible `roles/csr_delivery_openbao`) already grants
  write on `secret/csr-certs/*`; add the keys path (write + read for fetch),
  **no delete**, consistent with the other delivery paths.

## Hardening payoff

Once `host` storage is off by default and keys no longer live under `/root`, the
helper + keystore can move out of `/root/sslcerts` and the systemd sandbox can
tighten (`ProtectHome=true`, which is currently blocked because the sudo'd
helper + keys live under `/root`).

## Phases

1. **Setting scaffold** — `key_storage` (default `vault`) in the DB + admin UI;
   no behavior change yet (legacy `host` path still runs). Ship + review.
2. **Core** — generate in `PrivateTmp`; on `vault`, write the key to OpenBao and
   shred the host copy; wire UI download to fetch-from-vault / `return_once`.
3. **Per-template override + short-lived re-issue** policy.
4. **Migrate** legacy on-disk keys into the vault (admin sweep) + purge; retire
   the `/root/sslcerts/private` keystore; relocate helper/keys; tighten the
   systemd sandbox.

## Out of scope (for now)

- ACME *account* keys and the dashboard's own TLS key (separate lifecycles).
- HSM / PKCS#11-backed generation (a later option under the same `key_storage`
  seam).
