# Certinel — Certificate Delivery (shipping issued certs to destinations)

Status: **design** (proposed; no code yet). Companion to the v2 in-UI signing
work and the issuance-time validity control (short-lived certs). The driver:
a short-lived certificate (e.g. a 30-minute client cert) is worthless unless it
reaches its destination **automatically, quickly, reliably, and observably** —
no human in the loop.

## 1. Goal

After a certificate is issued, deliver the resulting material to where it's
actually used — a Linux host, a Kubernetes workload, a user/device, or a
secrets store — without a human moving files. Delivery must be **idempotent**
(re-deliver overwrites), **retried** (a failed 30-minute cert must not lapse
silently), and **auditable** (every delivery recorded; failures alert).

## 2. Where it plugs in

`backend/_attach_signed_cert()` is the single convergence point for *every*
issuance — manual upload, approve-&-sign, and renewal all flow through it (it
already verifies the pubkey, flips the job to `issued`, drops the cert to
`ISSUED_DIR`, fleet-tracks, fires `job.issued`, and emails). Delivery hooks in
**there**, so all producers get it for free.

Delivery runs **asynchronously** — the sign/issue response returns immediately;
a background pass performs delivery and updates status. This keeps issuance fast
(important for short-lived) and lets delivery retry independently.

New module **`backend/deliver.py`** mirrors the existing provider-seam pattern
(`notify.py`, `sign.py`, `ca_providers.py`): a registry of delivery providers
behind one `deliver(job, bundle, cfg)` dispatch, per-template configuration,
secrets via the server environment.

A **`certinel-deliver` systemd timer** (like `certinel-auto-renew` / `certinel-expiry-warn`)
re-attempts `pending`/`failed` deliveries with backoff — the reliability spine.
(Background passes have no Flask request context; entrypoints are re-exported
from `app.py` and guard `g`/`request`, per the existing convention.)

## 3. The private key — admin-selectable policy

The cert + chain are always safe for the server to hand out. The **private key**
is the sensitive part, and only exists server-side for **Generate** jobs
(External-submit jobs never had a server-side key → deliver cert+chain only).

Key handling is an **admin choice per template / destination** (`key_mode`):

- **`destination` — key-at-destination (no key in transit).** The destination
  generates its own key + CSR; the dashboard only ever ships the signed cert
  back. Most secure; recommended wherever the destination can do it.
- **`ship` — deliver the key with the cert** over an encrypted channel. Needed
  for endpoints that can't generate their own CSR. *(Initial testing mode: ship
  cert+key to the host the cert belongs to.)*
- **`vault` — key lives only in a credential store** (OpenBao / CyberArk); the
  destination's **service account fetches it** with its own auth. The
  production-grade default for many customers — the key never touches the
  destination's disk via us, and access is brokered + audited by the vault.

The key is never logged and only moves over TLS / Vault / SSH.

## 4. Delivery mechanisms (one provider per template)

| Provider | Model | Best fit | Key transport |
|---|---|---|---|
| **`pull`** — token bundle (`GET /api/jobs/<id>/bundle`, scoped token) | destination pulls | simplest trust; no inbound to targets, no creds *to* targets | dest pulls key (Generate) over TLS |
| **`openbao`** — write to Vault KV | dashboard → Vault → dest | short-lived + zero-trust; **already operated here** | key lands in Vault; dest fetches via AppRole/k8s auth |
| **`cyberark`** — write to CyberArk | dashboard → CyberArk → dest | enterprise customers standardized on CyberArk | as above, brokered by CyberArk |
| **`k8s`** — create/patch a TLS Secret | dashboard → cluster | in-cluster workloads (cert-manager-shaped) | key in a TLS Secret |
| **`ssh`** — SCP cert/key/chain + reload hook | dashboard → host | traditional servers (write path, then `nginx -s reload`) | key copied to host; needs SSH reach (more blast radius) |
| **`webhook`** — POST bundle to a receiver | dashboard → agent | dest runs an mTLS receiver | POST over mTLS |
| **(ACME server — already built)** | dest enrolls itself | **the cleanest short-lived story** | none (CSR-from-client) |

**Key point:** for any endpoint that can run an ACME client, the best
short-lived delivery is *not pushing at all* — point it at the dashboard's
built-in ACME server and let it self-renew. The push providers above are for
endpoints that **can't** do ACME.

## 5. Data model (additive migrations)

`cert_templates` gains:
| column | meaning |
|---|---|
| `delivery_backend` | `none` (default) \| `pull` \| `openbao` \| `cyberark` \| `k8s` \| `ssh` \| `webhook` |
| `key_mode` | `destination` \| `ship` \| `vault` |
| `delivery_target` | provider-specific (host, Vault path, namespace/secret, URL…) |
| `delivery_reload` | optional post-deliver command (ssh) |

`jobs` gains (audit + retry): `delivery_status` (`pending`/`delivered`/`failed`/
`n/a`), `delivery_detail`, `delivered_at`, `delivery_attempts`. Connection
secrets (SSH key path, Vault creds, CyberArk creds, kubeconfig) stay
**env-only**, never in the DB.

## 6. Flow

```
issue (any producer) → _attach_signed_cert  → job 'issued', delivery_status='pending'
certinel-deliver timer (or async)  → deliver.deliver(job, bundle, template_cfg)
                              → provider ships cert (+ key per key_mode)
                              → delivery_status='delivered' | retry on 'failed'
                              → fire job.delivered webhook + audit; alert on final failure
```

## 7. Security / STIG

- **Key in transit** only over TLS / Vault / SSH; never logged. Prefer
  `destination` or `vault` modes; `ship` is for testing / constrained endpoints.
- **New egress** — dashboard → destinations / Vault / cluster is new outbound on
  the box; allow per provider in firewalld + the service account.
- **Push credentials** (SSH key, Vault/CyberArk creds, kubeconfig) are scoped,
  least-privilege, env-mounted. SSH push has the largest blast radius — gate it.
- **Idempotent + retried** — a failed short-lived cert re-delivers; final
  failure raises an alert (you cannot let a 30-minute cert lapse silently).

## 8. Edition / capability

Automated delivery is a premium (Commercial) capability — `delivery.<backend>`
keys gated like the signing backends. Community keeps manual download.

## 9. Phasing

- **P1** — the `deliver.py` seam + DB + async/timer + status surfacing, with two
  providers that lean on existing infra: **`ssh`** (ship cert+key to the host the
  cert belongs to — the requested testing mode) and **`openbao`** (vault model,
  service-account fetch — the production default). Per-template config + key_mode
  in the admin Template editor.
- **P2** — `pull` token-bundle; `k8s` TLS Secret.
- **P3** — `cyberark`; `webhook` receiver agent; retry/backoff/alerting polish.
- Throughout — steer ACME-capable endpoints to the built-in ACME server.

## 10. Open questions

- **SSH auth model for `ssh` push:** a single dashboard SSH identity (csrapi key)
  authorized on destinations, vs per-destination creds from Vault? (Blast-radius
  + STIG egress decision before building host-push.)
- Default `delivery_target` = the job's `target_host` (the cert's CN/SAN) — ship
  the cert for host X to host X. Confirm that's the right default.
- For `vault`/`cyberark`: the path convention destinations agree to read from
  (e.g. `secret/csr-certs/<host>`), and which auth the service account uses.
