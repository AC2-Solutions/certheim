# Licensing the container distribution — entitled pull

Status: **proposed** (2026-06-22). Owner: AC2. Related: `licensing.py`,
[product-architecture.md](product-architecture.md), the AC2 license-server
(`ac2-solutions/licenses`, vm1022).

## Goal

Ensure the Certheim container images can't be **freely obtained or run** without a
valid entitlement, while keeping a single image (no edition branches) and
preserving air-gapped / on-prem deployment.

Non-goal: unbreakable anti-tamper. The app is interpreted Python in a
customer-controlled runtime — a determined operator can patch out a check.
Perfect DRM is impossible for self-hosted interpreted software; the model is
**feature-gating + entitled distribution + license binding + contract**, the same
posture as other commercial on-prem products. We do not pursue obfuscation DRM.

## Current state (already enforced at runtime)

`backend/licensing.py` already does offline, forge-proof entitlement:

- RSA-signed license, **embedded public key**, private key held offline by the
  vendor. No/invalid/expired license ⇒ **Community** (premium off).
- **Expiry** (`expires`) — past expiry silently drops to Community.
- **`max_domains`** — per-edition cap on signable domains (Commercial = 1).
- **Edition + explicit `entitlements[]`** gate every premium feature.
- **Host binding** — optional `bind_host` claim; a mismatch warns in logs + admin
  (soft, so a legitimate host move doesn't brick prod). Container-aware via
  `CERTHEIM_LICENSE_HOST`.
- Works identically in the container; the Helm chart mounts the license as a
  Secret (`CERTHEIM_LICENSE_FILE`), compose via an env/volume.

**Conclusion:** runtime entitlement is solid. The open gap is **distribution** —
the image itself is currently pullable by anyone holding the (shared) registry
credentials. This doc closes that with *entitled pull*.

## Decisions (confirmed)

- **One image**, entitlement enforced at pull *and* at runtime (defense in depth).
- **Entitled registry runs on/beside the license-server** (vm1022); the
  license-server is the registry **token authority**.
- **Seats/nodes deferred** — expiry + domains binding is enough for v1.
- Posture: standard feature-gating + license binding + legal. No DRM.

## Architecture — Docker registry v2 token auth

The customer's entitlement *is* their pull credential. We use the standard
[Docker registry v2 token authentication] flow with the license-server as the
auth service:

```
 customer ── docker login dl.certheim.io -u <customer-id> -p <pull-token>
 customer ── docker pull dl.certheim.io/certheim:<tag>
                │  401 + Www-Authenticate: realm=https://licenses.../v2/token
                ▼
 registry (registry:2, auth: token)
                │  client re-requests the token, basic auth (customer-id:pull-token)
                ▼
 license-server  /v2/token
                │  1. look up pull-token  → customer's signed license
                │  2. verify license (reuse licensing verify): signature OK?
                │  3. edition allows pull?  not expired?
                │  4. mint a short-lived registry JWT, scope repository:certheim:pull
                ▼
 registry serves the image (+ its SBOM/provenance attestations)
```

### Components

1. **Entitled registry** — `registry:2` on/beside vm1022, `auth.token`
   configured with `realm` = the license-server `/v2/token` URL, a `service`
   name, and the JWT-signing cert bundle. Public name `dl.certheim.io`
   (placeholder — confirm), fronted by Caddy/Cloudflare with TLS.

2. **license-server `/v2/token` endpoint** (new, in `ac2-solutions/licenses`) —
   implements the registry token protocol: authenticate `customer-id:pull-token`,
   resolve to the customer's license, run the **same verification** used to issue
   it (signature, edition, `expires`), and on success mint an RS256 registry JWT
   (scoped `repository:certheim:pull`, short TTL, signed by the registry's trust
   key). Deny (401/403) when the token is unknown/revoked or the license is
   expired/Community-only.

3. **Pull credential** — the portal issues, *alongside* the signed license, an
   opaque **pull token** (random, stored against the customer's license record).
   Why not the license blob as the docker password: licenses are large and
   rotating pull access shouldn't require re-issuing the license. The pull token
   is revocable independently and maps 1→1 to a license.

4. **Image sync** — CI keeps pushing the attested image to **private Docker Hub**
   (`ac2solutions/certheim`, the build source of truth). On each release a
   `skopeo copy --all` mirrors `:vX.Y.Z` / `:latest` (+ `-slim`) **with their
   attestations** into the entitled registry. (Pull-through caching from a private
   upstream + token auth is fiddly; an explicit mirror is simpler and keeps the
   attestations intact.)

### What this stops / doesn't

- **Stops**: anonymous or credential-sharing-at-scale image acquisition; pulling
  *new* images after a license lapses (the `/v2/token` check fails on expiry); a
  leaked pull token is revocable and time-boxed.
- **Doesn't stop**: a customer who already pulled an image and patches out the
  runtime gate. That is a **license violation** (contract) — the runtime gate +
  host-binding warnings make misuse self-evident, and the value (updates, support,
  signed images, the issuance portal, premium integrations) stays behind the
  subscription.

## Binding summary (v1)

| Binding | Enforced where | Status |
|---|---|---|
| Edition / feature entitlements | runtime (`licensing.py`) | done |
| Expiry | runtime **and** pull-time (`/v2/token`) | runtime done; pull-time new |
| `max_domains` | runtime | done |
| Host binding (soft) | runtime | done |
| Entitled image acquisition | pull-time (registry token auth) | **new** |
| Seats / nodes | — | deferred |

## Phases

1. **This doc.**
2. **Entitled registry + `/v2/token`** — stand up `registry:2` on/beside vm1022;
   add the token endpoint + pull-token issuance to the license-server; DNS + TLS
   for `dl.certheim.io`; CI/release `skopeo` mirror. Codify in Ansible.
3. **Issuance UX** — the portal shows the customer their license **and** their
   `docker login` + pull command; the setup-guide deployment generator references
   `dl.certheim.io` (instead of the raw Docker Hub repo) and emits the pull
   secret. Image references in chart/compose default to the entitled registry.
4. **(optional) cosign-sign** the published images so customers can verify
   authenticity (`cosign verify`), complementing the SBOM/provenance attestations.
5. **(optional) Seats** — add `max_nodes` to the license + soft enforcement, when
   a deal needs per-seat metering.

## Open items to confirm

- **Public hostname** for the entitled registry (`dl.certheim.io`? under an
  `*.ac2solutions.com` name? the eventual Certheim product domain?).
- **TLS source** (public ACME vs step-ca — customer-facing ⇒ public CA).
- Registry storage backend + retention (which tags to mirror/keep).

[Docker registry v2 token authentication]: https://distribution.github.io/distribution/spec/auth/token/
