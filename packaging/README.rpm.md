# Certheim (RPM)

Certheim certificate lifecycle management, installed as a **native Linux
service** — no containers, no Kubernetes.

## Install

The RPM is GPG-signed. On hosts that enforce `gpgcheck` (DISA STIG, most
hardened builds), import the Certheim public key once, then install:

```bash
sudo rpm --import RPM-GPG-KEY-certheim               # key id A16072AF9F5E7593
rpm -Kv ./certheim-<version>-1.x86_64.rpm            # expect: Signature … OK
sudo dnf install ./certheim-<version>-1.x86_64.rpm   # pulls nginx, python3, …
sudo certheim-setup                                  # configure + start
```

`RPM-GPG-KEY-certheim` ships with the release (and at
`/usr/share/doc/certheim/RPM-GPG-KEY-certheim` after install). Fingerprint:
`D245 9994 B9DD 0392 9E89 1E2B A160 72AF 9F5E 7593`.

`certheim-setup` is interactive. It picks the FQDN and TLS mode
(self-signed / bring-your-own / step-ca ACME), provisions nginx, creates the
`certinel` service account, builds the service virtualenv from the bundled
**offline wheelhouse** (works air-gapped), and starts the `certinel-api`
systemd service behind nginx on 443.

## Unattended install

Every prompt has an environment-variable override; set `ASSUME_DEFAULTS=yes`
to take defaults for the rest:

```bash
sudo FQDN=cert.example.com TLS_MODE=selfsigned ASSUME_DEFAULTS=yes certheim-setup
```

Apply a Commercial/Government license with `LICENSE_FILE=/path/to/license`.
Full variable list: the header of `/usr/share/certheim/install/online-install.sh`.

## Service

```bash
systemctl status certinel-api          # the app (gunicorn on 127.0.0.1:5002, fronted by nginx)
journalctl -u certinel-api -f
```

Timers `certinel-expiry-warn`, `certinel-auto-renew`, `certinel-deliver` and
`certinel-doctor` are enabled by setup.

## Upgrade

```bash
sudo dnf upgrade ./certheim-<newer>-1.x86_64.rpm
sudo certheim-setup                    # roll the new code onto the live paths (idempotent)
```

## Remove

```bash
sudo dnf remove certheim               # stops the service; leaves data + config
sudo certinel-uninstall                # optional: purge /opt/certinel, /var/opt/certinel, /etc/certinel
```

Runtime data (`/var/opt/certinel`), the database (`/var/lib/certinel`) and
configuration (`/etc/certinel`) are preserved on `dnf remove` by design.
