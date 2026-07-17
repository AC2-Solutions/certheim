# Certheim — Delivery Automation (making the last mile hands-free)

Status: **design** (proposed; no code yet). Extends
[cert-delivery-design.md](cert-delivery-design.md) (the async push/pull provider
seam in `backend/deliver.py`) and [endpoint-push-design.md](endpoint-push-design.md).
Builds on capabilities already shipped: the ACME **server**, EST/SCEP enrollment,
OpenBao KV delivery, the fleet inventory (source of truth + nightly scan), and
automated renewal.

## 1. Why push alone isn't enough

Today every delivery provider is a **push** from the control plane (SSH, F5 /
NetScaler / A10 / IIS APIs, K8s Secret, webhook, OpenBao KV), plus a pull-token.
Push is the weakest foundation to scale on:

- **Blast radius** — Certheim must hold write-credentials to every destination
  (an SSH key that can write `/etc/ssl` on the whole fleet is a prime target).
- **Reachability** — the control plane needs an inbound path to every host;
  NAT'd, firewalled, autoscaled, and air-gapped estates don't fit.
- **Brittle last mile** — reload / verify / rollback is per-provider and mostly
  fire-and-forget; a failed reload can silently serve a stale (or no) cert.
- **Renewal is a repeated push** — every 30/90-day cycle re-runs the same
  fragile push instead of the endpoint just keeping itself current.

The unlock is to **invert the direction wherever possible**: let the endpoint
enroll and renew itself, and keep install + reload at the edge where mature
tooling already lives. Certheim becomes the policy + CA + source-of-truth, not a
file-copier.

## 2. Principles (target model)

1. **Prefer endpoint-driven (pull / enroll) over control-plane push.** Push is a
   fallback for things that can't pull.
2. **One control plane, many transports.** A *destination* declares its transport
   (`acme` | `secret-store` | `agent` | `push:<provider>`); the control plane
   tracks state uniformly regardless.
3. **Verify-after-deploy is mandatory.** Every transport must confirm the
   endpoint is actually serving the delivered cert, not assume success.
4. **Least privilege.** No shared credential that can write to the whole fleet;
   each endpoint proves its own identity and fetches only what it's entitled to.
5. **Close the loop on the inventory.** "What we issued" and "what's actually
   served where" converge via the fleet scan → drift is a first-class signal.

## 3. The four workstreams

### D1 — ACME-first delivery (the endpoint enrolls itself)  *[highest leverage]*

The most automated delivery is *no delivery*. Certheim already runs an ACME
server; make it the primary delivery + renewal plane. An endpoint's existing
ACME client — Caddy, Traefik, nginx, certbot, Windows/IIS, K8s cert-manager —
handles issuance, install, reload, and renewal on its own.

- **Policy binding:** External Account Binding (EAB) ties each ACME account to a
  Certheim template / group / issuance policy, so a client can only obtain certs
  the policy permits. Mint EAB credentials per destination or per group in the UI.
- **Challenges:** `dns-01` via a Certheim-managed DNS provider, or `http-01`;
  internal-only names can use a profile-gated / pre-validated challenge.
- **Certheim's role:** CA + policy + approval gating + inventory. Every ACME
  order is recorded as a delivery event so the fleet view stays complete, and
  revocation flows through the existing CRL/OCSP.
- **Design points:** EAB account provisioning UI; mapping ACME orders back to
  templates; surfacing ACME-issued certs in inventory; reconciling ACME's
  fully-automated model with approval gating (solve via *pre-approved profiles*
  for low-risk names, hold-and-notify for sensitive ones).

Retires most bespoke push with the least new code and the broadest compatibility.

### D2 — Secret-manager-native publish (let the platform distribute)

Generalize the OpenBao-KV provider into a **secret-store** provider family:
Vault / OpenBao KV, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager,
Kubernetes Secret. Certheim writes the material to the store the workload already
reads; the platform's existing rotation machinery — External Secrets Operator,
the Secrets Store CSI driver, Vault Agent, a reloader controller — distributes
and reloads it.

- "Delivery" becomes "publish to the source of truth; the platform fans out."
- **Reload:** many platforms auto-detect a new version; optionally bump an
  annotation / emit a rotation event to trigger a rollout.
- **Design points:** per-store auth (IAM role / workload identity, no long-lived
  keys), path templating, key-handling modes (cert-only vs cert+key), and
  rollback via the store's native versioning.

Near-zero friction for cloud-native fleets.

### D3 — Certheim delivery agent (pull + install + verify + self-renew)

A small static-binary daemon on each host that can't (or shouldn't) speak ACME —
legacy services, appliances behind jump hosts, air-gapped enclaves.

- **Identity:** bootstrapped once from an enrollment token into an mTLS client
  identity (the agent uses Certheim's own EST/ACME to get its cert — dogfood).
  No shared fleet key.
- **Flow:** pulls the assignments for the workloads it owns (long-poll / gRPC
  stream / interval), writes atomically, runs the reload hook, **verifies** the
  served cert, and reports status back.
- **Self-renewal:** the agent owns the renewal timer locally, so renewal
  continuity is solved at the edge rather than as a repeated central push.
- **Reachability:** outbound-only → works behind NAT / firewalls; an offline
  relay covers true air-gap (ties into the Government offline-transfer work).
- **Design points:** identity bootstrap + rotation; the assignment model
  (agent ↔ destinations via fleet inventory + label selectors); the reload-hook
  contract; verification; air-gap/offline mode; signed agent auto-update; RBAC so
  an agent fetches only its entitled certs.

This is the biggest build but it retires the SSH-push trust model entirely.

### D4 — Hardened push + drift re-deliver (fix what exists, now)  *[lowest risk]*

Keep push for gear that genuinely can't pull or enroll, but make it trustworthy:

- **Atomic write** (temp + rename), **post-deploy TLS verification** (connect to
  the endpoint, compare the served leaf to what was delivered), **automatic
  rollback** on reload failure.
- **Staged / canary rollout** with concurrency caps across a destination set.
- **Drift detection** — reuse the nightly fleet scan to compare served-vs-expected
  and **re-deliver on drift or impending lapse**, instead of assuming the last
  push still holds.

An in-place upgrade to the existing providers; ships first and de-risks the rest.

## 4. The unifying layer — Destinations + a state machine

Delivery is currently a per-template attribute. Promote **Destination** to a
first-class object (like the fleet-assignment RBAC already does for visibility):
a labelled target with a transport and config, mapped to certs by selector.

Every `(cert, destination)` pair runs one uniform state machine —
`desired → in-flight → delivered → verified → drift | failed` — with retry/
backoff, audit, and alerting (all reusing the existing delivery event pipeline).
The transport differs; the tracking, verification, and drift handling do not.
This is what makes "really automated" measurable: at any moment you can answer
*is every destination serving the cert it should be?*

## 5. Sequencing

| Wave | Work | Rationale |
| --- | --- | --- |
| 1 | **D4** hardening + drift, **+ the Destination/state-machine layer** | Lowest risk; upgrades what exists and gives every later transport a home |
| 2 | **D1** ACME-first (EAB + account provisioning + inventory mapping) | Highest leverage; retires most bespoke push |
| 3 | **D2** secret-store family | Cloud-native coverage, mostly reuses the seam |
| 4 | **D3** agent | Biggest build; covers the long tail (legacy, air-gap, non-ACME) |

## 6. Edition mapping

All four are Commercial+ (delivery is a paid capability; Community keeps the
locked-upsell surface). Government adds the **air-gapped agent** (offline relay /
cross-domain transfer) and FIPS-validated agent builds.

## 7. Open questions / risks

- **ACME vs approval gating** — reconcile ACME's automation with hold-for-approval
  on sensitive names (profiles + policy).
- **Agent supply chain** — footprint, signed auto-update, and blast radius of a
  compromised agent (scoped identity, per-agent RBAC).
- **Secret-store auth sprawl** — one credential/identity per store type.
- **Backwards compatibility** — migrate the existing per-template delivery config
  into Destinations without breaking configured installs.

## 8. What we reuse (already built)

`deliver.py` provider seam · `_attach_signed_cert()` convergence point ·
delivery retry/backoff + alert events · the ACME **server** · EST/SCEP ·
OpenBao KV delivery · the fleet inventory + nightly scan (drift) · automated
renewal. The roadmap is mostly *composition and inversion* of pieces that exist,
not green-field.
