# CSR Dashboard v2.9.0

_Released 2026-06-19. 1 change since v2.8.0._

## Features

- **licensing:** redraw to full-product-capped-by-scale Community tier (`a938da7`)
  Community (free) = the full single-instance product capped at N active certs (default 25, admin-
  tunable via community_cert_limit). The core loop is free: in-UI signing via OpenBao/standalone
  Windows CA/ACME client, automated renewal, fleet, audit, SMTP, local/CAC auth. Commercial removes
  the cap (scale.unlimited_certs) + adds enterprise breadth (CyberArk/EJBCA/Venafi/AWS PCA, ACME
  server, chat/email integrations). Government = + public-sector pack.
  Cap enforced once, in _attach_signed_cert (covers approve&sign + manual upload + auto-renew);
  renewals (renewed_from) are exempt. Usage surfaced on Admin->License.
