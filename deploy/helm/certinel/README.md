# Certinel Helm chart

Deploy Certinel (certificate lifecycle platform) on any Kubernetes cluster.

```bash
helm install certinel ./deploy/helm/certinel \
  --namespace certinel --create-namespace \
  --set ingress.host=certinel.example.com
```

The app runs **container-mode**: no sudo helper, and TLS + CAC/client-cert auth
are terminated at the **ingress** (the verified identity is forwarded as
`X-Client-*` headers). A small nginx sidecar serves the static frontend and
proxies the API. SQLite on a PVC by default (single replica); point at an
external PostgreSQL for HA.

## Common values

| Key | Default | Notes |
|-----|---------|-------|
| `image.tag` | chart appVersion | use `<ver>-slim` for the Debian-slim image |
| `db.backend` | `sqlite` | or `postgres` (+ `db.postgres.url`/`existingSecret`) |
| `license` | `""` | signed license blob (mounted, `CSR_LICENSE_FILE`) |
| `ingress.host` | `certinel.example.com` | required |
| `ingress.tls.secretName` | `certinel-tls` | TLS cert (cert-manager or pre-created) |
| `ingress.clientCert.enabled` | `false` | CAC/mTLS at the ingress; `caSecret` = client-CA bundle |
| `openbao.enabled` | `false` | in-UI OpenBao signing (`addr`,`role`,`roleId`,`secretId`) |
| `persistence.size` | `5Gi` | SQLite DB volume; `dataSize` for issued certs/keys |

PostgreSQL example:

```bash
helm install certinel ./deploy/helm/certinel \
  --set db.backend=postgres \
  --set db.postgres.url='postgresql://certinel:PW@pg:5432/certinel' \
  --set replicaCount=2 --set ingress.host=certinel.example.com
```

Migrate an existing SQLite deployment onto Postgres first with
`tools/certinel-db-migrate --to <dsn>` (see the app's Admin → Database page).
