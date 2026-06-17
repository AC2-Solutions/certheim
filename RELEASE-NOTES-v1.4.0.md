# CSR Dashboard v1.4.0

Turns the dormant authentication backend (shipped in v1.3.0) into a complete,
working feature: a login gate, username/password authentication, a unified
first.last identity, admin-managed passwords and names, and self-service group
management. A host is configured for exactly one method — CAC/mTLS OR
username/password — chosen at install time and adjustable from the admin UI.

See the conversation/commit history for the full per-area breakdown:
- Authentication: login gate, single-mode (CAC or password), sign-in/out,
  self-registration with STIG password policy + trusted domain.
- Identity: unified first.last for all users; CAC names auto-parsed from the
  DoD CN; admin name editing regenerates the username.
- Administration: Authentication settings tab (mode/domain/approval),
  pending-user approve/deny in Users tab, admin set/reset password.
- Groups: owners promote/demote/add/remove; members can leave themselves only;
  a group always keeps at least one owner.
- Changed: DoD banner is a link+modal with an "I agree" gate, not a forced
  interstitial.
- Schema: adds first_name/last_name to users (additive, auto-migrated).

NOTE on CAC identity: on an mTLS box, nginx must verify and forward the client
cert DN (ssl_verify_client on + DoD CA bundle + X-Client-DN/Verify headers) or
CAC users resolve to an ip-based identity. That is nginx/PKI config, separate
from the application.
