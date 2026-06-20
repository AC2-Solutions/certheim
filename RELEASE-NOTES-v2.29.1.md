# CSR Dashboard v2.29.1

_Released 2026-06-20. 1 change since v2.29.0._

## Fixes & improvements

- **truststore:** make SSH push work under the certinel-api sandbox (`1c883f7`)
  Live-firing the trust-store SSH push from inside the certinel-api unit (ProtectHome=true,
  PrivateTmp=true) surfaced two bugs a plain shell hid:
  - push_ssh staged the bundle and installed it in two separate ssh calls using a $$-based remote
    temp path. $$ is the remote shell PID and differed between the two sessions, so the install
    couldn't stat the staged file. Collapse to a single ssh round trip: the bundle is piped on
    stdin and the remote shell mktemp's its own file, installs, and cleans up in one shell.
  - ProtectHome masks the service user's $HOME, so ssh couldn't persist known_hosts (noisy 'Could
    not stat ~/.ssh' + on a strict host a hard fail). Pin UserKnownHostsFile=/dev/null with
    accept-new. Apply the same to the deliver.py SSH provider, which shares the pattern.
  Proven: a real Vault-backed push from a systemd-run replica of the certinel-api sandbox now
  installs the CA into the target's trust (update-ca-trust extract).
