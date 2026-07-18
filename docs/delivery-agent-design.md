# Certheim — Delivery Agent (Wave 4 of delivery automation)

Status: **design** (proposed; no code yet). Child of
[delivery-automation-design.md](delivery-automation-design.md) §3-D3. Waves 1-3
are built: Destinations + the per-(cert, destination) state machine + hardened
push + drift (W1), ACME-first with EAB (W2), cloud secret stores (W3). The
agent covers the remaining tail: hosts that can't speak ACME and shouldn't be
pushed to — legacy services, hosts behind NAT/firewalls, jump-host-only
segments, and (later) air-gapped enclaves.

## 1. What it is

A small daemon on the endpoint that **pulls** its certificate material from
Certheim, installs it atomically, runs the reload hook, verifies the service
picked it up, and reports back — outbound-only HTTPS, no inbound path to the
fleet, no central SSH key that can write to every host.

House constraints: **single-file, stdlib-only Python 3** (like the rest of the
product - no SDKs, no pip), shipped in-repo under `agent/`, installed by RPM /
tarball / one curl, run by a systemd unit.

## 2. Trust model

- **Enrollment token** (the only shared secret, one-time): admin mints it in
  the UI (same UX as EAB credentials — shown once), optionally pre-naming the
  agent and pinning the host. `certheim-agent enroll --url ... --token ...`
  exchanges it for the agent's **own credential** and writes
  `/etc/certheim-agent/agent.conf` (0600).
- **Agent credential**: a per-agent bearer token (random 256-bit; only its
  SHA-256 stored server-side). All subsequent calls authenticate with it.
  Compromise blast radius = that one agent's assigned bundles; revoking the
  agent invalidates the token and (optionally) re-queues its pairs elsewhere.
  mTLS is deliberately NOT required in v1: every supported install fronts the
  app with nginx/Caddy and header-auth complications outweigh the win; the
  token rides TLS the proxy already terminates. (mTLS/SPIFFE can layer on
  later via the existing X-Client-* header path.)
- **Server → agent trust**: none needed. The agent never accepts inbound
  connections; it polls.

## 3. How it maps onto what exists (the key design economy)

The agent is **a transport for the Wave 1 state machine**, not a new system:

- New Destination transport **`agent`**: `host` = the agent's name, `target` =
  the install directory on the endpoint, `reload_cmd` as usual, `verify_tls` /
  `verify_port` reuse the existing probe fields (the agent runs the probe
  locally; the server may re-probe reachable endpoints for drift exactly as
  today).
- Issuance fans out `desired` pairs exactly as for every other transport. The
  server-side provider for `agent` is a **no-op** (state advances only when
  the agent reports); the timer's backoff/abandon machinery still applies via
  a `delivery_agent_deadline` (a pair not delivered within N minutes of
  becoming desired → `failed`, alert — a dead agent can't fail silently).
- **Renewal continuity falls out for free**: server-side auto-renew issues the
  new cert → new `desired` pairs → the agent's next poll picks them up. The
  agent needs no renewal logic at all.
- Drift: the agent re-verifies its installed material on every poll (files
  present, served leaf matches when verify is on) and reports `drift`, feeding
  the same state + alerts as W1-P4.

## 4. Protocol (all outbound HTTPS from the agent)

| Call | Purpose |
| --- | --- |
| `POST /api/agent/enroll` `{token, hostname, facts}` | one-time: returns `{agent_id, credential}`; token consumed |
| `GET /api/agent/work` (Bearer) | the agent's due pairs: `[{pair_id, destination: {target, reload_cmd, verify...}, bundle: {certificate, chain?, private_key?}}]` — key material included only per the destination's key-handling mode |
| `POST /api/agent/report` (Bearer) | `[{pair_id, status: delivered\|verified\|failed\|drift, detail}]` → drives `delivery_state` (same transitions/events/webhooks as deliver_pair) |
| `POST /api/agent/heartbeat` (Bearer) | liveness + agent version + facts; powers the UI's last-seen/health |

Poll cadence: long-poll `work` with a jittered interval (default 60s; the
response carries `poll_seconds` so the server can back agents off). Payloads
are small; a thousand agents at 60s is trivial load.

## 5. Agent behavior (install loop)

1. Fetch work. For each pair: write to `<target>/<name>.new`, keep `.prev`,
   `mv -f` into place (the Wave-1 hardened-push sequence, executed locally).
2. Run `reload_cmd`; on failure restore `.prev`, re-run reload, report
   `failed` with detail (server retries per backoff).
3. If verify is configured: probe `localhost:<verify_port>` (SNI = the cert's
   CN) and byte-compare the served leaf; report `verified` or `failed`.
4. Report; on every poll re-check installed pairs and report `drift` when the
   on-disk/served material no longer matches.
5. Private keys: written 0600, owner configurable per destination via
   `key_owner` (new optional Destination column, also useful for ssh push).

## 6. Schema (additive, house pattern)

- `agents` — id, name UNIQUE, hostname, token_hash, status
  (active|revoked), enrolled_at, last_seen, version, facts_json.
- `agent_enroll_tokens` — token_hash PK, name, host_pin, created_at/by,
  used_by_agent, revoked. (Mint/list/revoke mirrors `acme_eab_keys`.)
- `destinations` + `key_owner` TEXT (optional).
- No new state table — `delivery_state` already models everything.

## 7. Admin surface

- **Automation → Delivery** gains an **Agents** card: enrolled agents
  (name, host, version, last-seen with staleness pill, assigned destinations,
  pair health), enrollment-token mint (one-time display with the copy-paste
  `certheim-agent enroll ...` line), revoke (deactivates token + marks agent
  revoked + alerts on its now-orphaned pairs).
- Destination form: transport `agent` → host field becomes "agent name"
  (dropdown of enrolled agents).
- Setup wizard page: install (RPM/tarball), enroll, systemd unit, SELinux
  note (`/opt` not `/home`, restorecon — the fleet's own hard-won lessons).

## 8. Capability + editions

`delivery.agent` — Commercial+ (env: none; works air-gap-adjacent since only
outbound HTTPS to the dashboard is needed). Excluded from Starter (it is
fleet-scale tooling, like the device pushes). Government later adds the
offline relay variant (cross-domain transfer of work/report batches — ties to
the G6 air-gap work), out of scope here.

## 9. Delivery of the agent itself

`agent/certheim_agent.py` + `agent/certheim-agent.service` in-repo; packaged
into the existing RPM (subpackage `certheim-agent`) and the offline bundle;
also downloadable from the dashboard (`GET /api/agent/download`, admin-gated)
so a customer can bootstrap a host with one curl. Version handshake via
heartbeat; the server flags outdated agents in the UI (no auto-update in v1 —
signed auto-update is a follow-up).

## 10. Failure modes addressed

| Failure | Handling |
| --- | --- |
| Agent dies / host offline | pairs pass `delivery_agent_deadline` → failed + alert; heartbeat staleness pill |
| Reload breaks the service | local rollback to `.prev` + reload, report failed (server backoff/retry) |
| Endpoint serves stale cert after reload | local verify fails → failed; plus ongoing drift re-checks |
| Credential leak | revoke agent (token hash dead) — scoped to that agent's bundles |
| Enrollment token leak | one-time use + revocable + optional host pin |
| Clock-skew / replay | bearer token over TLS; no signed timestamps needed in v1 |

## 11. Phasing

| Phase | Scope |
| --- | --- |
| W4-P1 | Control plane: schema, enroll/work/report/heartbeat API, `agent` transport + deadline in the timer, admin CRUD |
| W4-P2 | The agent (stdlib Python, install loop §5) + systemd unit + RPM subpackage + download endpoint |
| W4-P3 | UI (Agents card, destination integration) + wizard page + docs |
| W4-P4 | Live proof: enroll an agent on a lab VM, deliver + verify + drift + revoke end-to-end |

## 12. Open questions

1. `work` long-poll vs plain interval poll — v1 proposes plain interval with
   server-tunable `poll_seconds` (simplest; long-poll is a drop-in later).
2. Should revoking an agent auto-requeue its pairs to nothing (alert only) or
   allow re-pointing destinations at a replacement agent? v1: alert only;
   re-pointing = admin edits the destination's agent name.
3. RPM subpackage vs separate artifact — proposal: subpackage (one pipeline).
