# CSR Dashboard v2.21.0

_Released 2026-06-19. 2 changes since v2.20.1._

## Features

- P2 cert-delivery providers — pull (token-bundle) + k8s (TLS Secret) (`761a05c`)
  pull: dashboard stores the issued bundle behind a scoped, single-use, short-lived token; the
  destination fetches it at GET /deliver/pull/<token> (JSON / pem / cert). No push path, no Vault
  grant — works through a one-way firewall toward the dashboard. New delivery_pulls table;
  routes_deliver.py public blueprint; csr-deliver timer purges expired tokens.
  k8s: server-side-apply a kubernetes.io/tls Secret into <ns>/<secret> (cred from Vault secret/csr-
  delivery-k8s/<cluster>); requires key_mode=ship.
  Adds delivery.pull + delivery.k8s capabilities, admin dropdown options with per-backend target
  hints, smoke tests (pull lifecycle/formats, k8s guards, k8s env-gating), runbook sections, and the
  k8s cred path to the policy doc.

## Fixes & improvements

- serve pull endpoint under /api/ so it rides the existing nginx proxy (`708b5d3`)
  Only /csr/api/ is proxied to Flask; /deliver/* fell through to the SPA. Move the route to
  /api/deliver/pull/<token> (no per-deployment nginx change).
