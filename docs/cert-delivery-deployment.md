# Certificate Delivery — Deployment Runbook (per client)

Turnkey steps to enable **automated certificate delivery** on a new CSR Dashboard
deployment. Design rationale lives in `cert-delivery-design.md`; this is the
hands-on checklist. Do the OpenBao grants **once per client**, then configure
delivery per certificate template in the admin UI.

Providers covered: **`openbao`** (write the cert bundle to Vault KV) and **`ssh`**
(scp the cert/key to the destination host, creds fetched from Vault).

---

## 0. Prerequisites

- The dashboard already signs via OpenBao (it has an **AppRole** with a
  `*-pki-sign` policy). Note the **role name** — find it with the role's own
  token:
  ```bash
  # on the dashboard host, using its env creds:
  source /etc/csr-dashboard/csr-dashboard.env
  TOK=$(curl -s --cacert "$CSR_OPENBAO_CA_FILE" -X POST \
    "$CSR_OPENBAO_ADDR/v1/auth/approle/login" \
    -d "{\"role_id\":\"$CSR_OPENBAO_ROLE_ID\",\"secret_id\":\"$CSR_OPENBAO_SECRET_ID\"}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["auth"]["client_token"])')
  curl -s --cacert "$CSR_OPENBAO_CA_FILE" -H "X-Vault-Token: $TOK" \
    "$CSR_OPENBAO_ADDR/v1/auth/token/lookup-self" | python3 -m json.tool | grep -E 'role_name|policies'
  ```
  In the AC2 reference deployment the role is **`csr-dashboard`**; substitute
  `<ROLE>` below.
- A KV **v2** secrets engine (default mount `secret`). The provider writes to
  `secret/csr-certs/<host>` and (for ssh) reads `secret/csr-delivery-ssh/<host>`.

> All `bao` commands below need an **admin/root** token. On a K8s-hosted OpenBao
> use the recovery-key flow (§4); on a VM-hosted OpenBao log in with your admin
> token first.

---

## 1. OpenBao ACL policy

Create policy **`csr-delivery`** — write delivered bundles, read SSH creds. It
deliberately grants **no delete** (the dashboard must never remove a delivered
cert) and read-only on the SSH-cred path.

```hcl
# csr-delivery.hcl
# Cert bundles the dashboard writes (openbao provider):
path "secret/data/csr-certs/*"            { capabilities = ["create", "update", "read"] }
path "secret/metadata/csr-certs/*"        { capabilities = ["read", "list"] }
# Per-destination SSH credentials the dashboard reads (ssh provider):
path "secret/data/csr-delivery-ssh/*"     { capabilities = ["read"] }
path "secret/metadata/csr-delivery-ssh/*" { capabilities = ["read", "list"] }
# Per-cluster Kubernetes API credentials the dashboard reads (k8s provider):
path "secret/data/csr-delivery-k8s/*"     { capabilities = ["read"] }
path "secret/metadata/csr-delivery-k8s/*" { capabilities = ["read", "list"] }
```

```bash
bao policy write csr-delivery csr-delivery.hcl
```

> If you only need the `openbao` provider, drop the `csr-delivery-ssh` and
> `csr-delivery-k8s` lines. The `pull` provider needs **no** Vault grant at all.

> **Codified path:** this policy + AppRole attach is an Ansible role —
> `roles/csr_delivery_openbao` in the `ansible` repo. Add the deployment's
> AppRole to `csrd_target_roles` and run
> `ansible-playbook playbooks/csr_delivery_openbao.yml -e bootstrap=true`
> instead of the manual `bao` steps in §1–§2.

## 2. Attach it to the dashboard's AppRole

Keep the existing policies and **add** `csr-delivery` (replace the list with the
union — list the current ones first if unsure):

```bash
bao read auth/approle/role/<ROLE>/policies          # see current set
bao write auth/approle/role/<ROLE>/policies \
  policies="default,<existing-pki-sign-policy>,csr-delivery"
```

Verify:
```bash
bao read auth/approle/role/<ROLE>/policies          # should include csr-delivery
```

That's the only OpenBao change for the `openbao` provider. Continue to §3 for
`ssh`.

---

## 3. SSH provider — per-destination setup

For each destination host the dashboard ships to:

1. **A delivery user on the destination** with write access to the cert
   directory and (if it reloads a service) a scoped sudoers entry:
   ```bash
   useradd -r -m -s /bin/bash certdeliver
   install -d -o certdeliver -g certdeliver -m 0750 /etc/ssl/delivered
   # optional reload, least-privilege:
   echo 'certdeliver ALL=(root) NOPASSWD: /bin/systemctl reload nginx' \
     > /etc/sudoers.d/certdeliver
   ```
2. **An SSH keypair** for that destination; authorize the public key:
   ```bash
   ssh-keygen -t ed25519 -f ./deliver_<host> -N '' -C "csr-delivery@<host>"
   ssh-copy-id -i ./deliver_<host>.pub certdeliver@<host>   # or append to authorized_keys
   ```
3. **Store the private key + user in Vault** at `secret/csr-delivery-ssh/<host>`
   (the dashboard reads it at delivery time):
   ```bash
   bao kv put secret/csr-delivery-ssh/<host> \
     username=certdeliver port=22 \
     private_key=@./deliver_<host>
   rm -f ./deliver_<host> ./deliver_<host>.pub        # don't leave keys on disk
   ```

The dashboard authenticates to each host with that per-destination key — no
single shared key, and the key never leaves Vault except into the dashboard's
memory for the one scp.

---

## 4. K8s-hosted OpenBao — minting an admin token

If OpenBao runs in Kubernetes (no standing admin token), apply §1–§2 with a
short-lived root token from the recovery-key quorum, **revoked at the end**.
Reference play: `/var/ansible/playbooks/openbao_root_token.yml` (imports, sets
`bao_root_token`); wrap the policy/role writes in `block:` and revoke in
`always:` (see `playbooks/rotate.yml` for the pattern). Run as the operator that
holds the recovery keys / kube access. **Never leave a generated-root token
un-revoked** (they don't auto-expire).

---

## 5. Dashboard configuration

1. **Env (optional)** — override the KV mount/base if not the defaults
   (`secret` / `csr-certs`) in `/etc/csr-dashboard/csr-dashboard.env`:
   ```
   # delivery_openbao_kv_mount and delivery_openbao_base are app_settings,
   # set in the admin UI or seeded here; defaults are secret / csr-certs.
   ```
2. **Per template (Admin → Templates → Edit signing):**
   - **Delivery** = `OpenBao KV` or `SSH host`.
   - **key_mode** = `destination` (cert only — most secure), `ship` (cert+key),
     or `vault` (key into the store, fetched by a service account).
   - **target** = for `openbao`, the KV base path (blank = `csr-certs`); for
     `ssh`, the remote directory (blank = a sensible default; host = the cert's
     CN/`target_host`).
3. The **`delivery.openbao` / `delivery.ssh` / `delivery.pull` / `delivery.k8s`**
   capabilities are Commercial — a licensed (or `CSR_ENTITLEMENTS`-overridden)
   deployment.

---

## 5b. P2 providers — `pull` and `k8s`

### `pull` (token-bundle — destination fetches)

No push path and **no Vault grant**: the dashboard stores the issued bundle and
hands back a scoped, single-use URL the destination fetches. Ideal when the
dashboard can't reach the destination but the destination can reach the
dashboard (one-way firewall), or for a human/script to grab a short-lived cert.

- **Env:** set **`public_base_url`** (admin setting) to the dashboard's external
  URL so the returned link is absolute (e.g. `https://csr.example.com/csr`).
  Optional: `delivery_pull_ttl` (seconds, default `3600`) and
  `delivery_pull_max_uses` (default `1`).
- **Per template:** Delivery = `pull token`; `key_mode` controls whether the key
  is included in the bundle. No target field.
- **Fetch:** `GET <public_base_url>/api/deliver/pull/<token>` → JSON
  `{certificate, private_key?}`; `?format=pem` → cert(+key) PEM; `?format=cert`
  → leaf only. The token is consumed on fetch and 404s afterward.

### `k8s` (Kubernetes TLS Secret)

Server-side-applies a `kubernetes.io/tls` Secret into a cluster namespace.
Requires `key_mode = ship` (a TLS Secret needs `tls.key`).

1. **Per-cluster credential in Vault** at `secret/csr-delivery-k8s/<cluster>`:
   ```bash
   bao kv put secret/csr-delivery-k8s/<cluster> \
     api_server="https://<k8s-api>:6443" \
     token="<serviceaccount-token>" \
     ca_cert=@/path/to/cluster-ca.crt        # optional; omit to use system trust
   ```
   The service account needs `create`/`patch` on `secrets` in the target
   namespace(s) — e.g. a Role granting `["get","create","patch"]` on
   `secrets` + a RoleBinding.
2. **Per template:** Delivery = `Kubernetes Secret`; `key_mode = ship`;
   **target** = `<namespace>/<secret>` (or `<cluster>/<namespace>/<secret>` to
   pick a non-default cluster; default cluster name is the `delivery_k8s_cluster`
   setting).

---

## 5c. P3 providers — `webhook` and `cyberark`

### `webhook` (POST to a receiver)

POSTs the bundle as JSON (`{event, target_host, certificate, private_key?}`) to
a receiver URL. **https only.** Optionally signed + mutually authenticated from
Vault `secret/csr-delivery-webhook/<host>` `{secret, ca_cert?, client_cert?, client_key?}`:

- `secret` → an `X-CSR-Signature: sha256=<hmac>` header the receiver verifies
  over the raw body.
- `client_cert`/`client_key` → mTLS to the receiver; `ca_cert` pins the
  receiver's TLS.
- With no Vault cred it's an unsigned POST (for receivers gated by network/mTLS
  alone).

**Per template:** Delivery = `webhook receiver`; **target** = the https URL.

### `cyberark` (CyberArk Conjur)

Writes the cert to the Conjur variable named by **target**, and the key (when
`key_mode = ship`) to `<target>/key`. Config is admin-set; the API key is
env-only:

```
# /etc/csr-dashboard/csr-dashboard.env
CSR_CYBERARK_URL=https://conjur.example.com
CSR_CYBERARK_ACCOUNT=myConjurAccount
CSR_CYBERARK_LOGIN=host/csr-dashboard
CSR_CYBERARK_API_KEY=<api-key>
# CSR_CYBERARK_CA_CERT=<pem>   # optional, pin Conjur's TLS
```

The Conjur host/identity needs `update` on those variables.

---

## 5d. Retry, backoff & alerting

Delivery runs inline on issue and is retried by the **`csr-deliver` timer**.
Failures back off exponentially (2 min → capped at 1 h) up to
`delivery_max_attempts` (default 8); after that the job is **`abandoned`** and a
**`job.delivery_failed`** event fires (wire it to chat/email/a webhook so a
short-lived cert can't lapse unnoticed). A successful delivery fires
**`job.delivered`**. Both events are in the admin webhook subscription list.

---

## 6. Verify

- Issue (or re-deliver) a cert under a delivery-enabled template. Delivery runs
  inline on issue; the **`csr-deliver` timer** (every 2 min) retries
  pending/failed.
- **openbao:** `bao kv get secret/csr-certs/<host>` shows `certificate` (+
  `private_key` per key_mode).
- **ssh:** the cert file appears in the destination directory; the reload (if
  set) ran.
- The job's **delivery status** (delivered / failed + detail) shows in the UI
  and the audit log; failures alert and retry.

---

## Per-client quick checklist

- [ ] Note the dashboard's AppRole **role name**.
- [ ] `bao policy write csr-delivery csr-delivery.hcl`.
- [ ] Attach `csr-delivery` to the AppRole (union with existing).
- [ ] (ssh) Per destination: delivery user + authorized key + `secret/csr-delivery-ssh/<host>`.
- [ ] Configure delivery + key_mode per template in the admin UI.
- [ ] Issue a test cert; confirm it lands; check the job's delivery status.
