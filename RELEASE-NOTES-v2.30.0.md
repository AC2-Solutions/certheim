# CSR Dashboard v2.30.0

_Released 2026-06-20. 1 change since v2.29.1._

## Features

- **install:** interactive installer + configurable service account (`015bfcb`)
  The online installer is now interactive: on a TTY it walks the operator through the environment-
  specific variables (service account, FQDN/URL, TLS source, auth mode, email, OpenBao, license)
  with sensible defaults, and confirms before acting. Every prompt is still overridable by an env
  var (+ ASSUME_DEFAULTS=yes) so unattended/CI installs keep working.
  Service account is now a first-class variable (default csrapi), threaded end to end:
  useradd/groupadd, directory + config + venv ownership, sudoers, and the systemd units'
  User=/Group= (deploy.sh renders the chosen account into the units and substitutes the manifest's
  :csrapi group). deploy.sh reads the choice from /etc/csr-dashboard/install.conf; with the csrapi
  default everything is byte-identical to before, so existing deployments are unaffected.
  TLS source is selectable: self-signed (default), bring-your-own (cert+key paths), or step-ca/ACME
  — the last bootstraps trust (--install), issues the leaf via a provisioner, and installs certinel-
  tls-renew.{service,timer} for daily auto-renewal (the 'proper auto-renew' path). bash -n gates the
  installer in CI.
