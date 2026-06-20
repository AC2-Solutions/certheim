# CSR Dashboard v2.29.0

_Released 2026-06-20. 1 change since v2.28.1._

## Features

- **truststore:** in-app CA trust store with build + fleet distribution (`163babb`)
  Admins upload root/intermediate CAs in the UI (Admin -> Trust store), Certinel parses/validates
  them via the system openssl (FIPS-clean, no bundled crypto), assembles one CA bundle, and
  distributes it three ways so a whole fleet trusts the same CAs without anyone SSHing in to hand-
  edit anchors:
  - install on the Certinel host itself (helper install-ca-bundle subcommand -> update-ca-trust /
    update-ca-certificates, auto-detected)
  - push over SSH to fleet targets, reusing the delivery SSH credential convention (secret/csr-
    delivery-ssh/<host>) and running the host trust tool
  - a token-scoped pull endpoint + generated one-line install script for hosts the app can't reach
    (air-gapped / one-way firewall / SaaS)
  New: backend/truststore.py + routes_truststore.py, trust_certs/trust_targets/ trust_pulls tables,
  helper/csr_dashboard_helper.d/30-truststore.sh, Trust store admin panel, capabilities trust.store
  + trust.distribute.ssh (SSH push gated on a credential manager; pull + local install work
  everywhere). Bundle is public CA material (no private keys), so pull tokens are reusable within
  their TTL; expired tokens are GC'd by the certinel-deliver timer. 3 smoke tests; manifests
  updated.
