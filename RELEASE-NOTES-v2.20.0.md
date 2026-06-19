# CSR Dashboard v2.20.0

_Released 2026-06-19. 1 change since v2.19.1._

## Features

- admins can create users from the Users panel (`cd9d18f`)
  POST /api/admin/users is now mode-aware: in LOCAL mode it takes first/last + email + an initial
  password (admin-supplied or auto-generated, policy-checked) and creates a login-ready account with
  an auto-derived first.last username; in mTLS mode it keeps the CAC-DN pre-create. A "+ Create
  user" button + modal in Admin → Users drives it, showing the generated temp password once. Smoke:
  mtls create + duplicate 409 + temp-password policy compliance.
