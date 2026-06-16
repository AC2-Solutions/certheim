# CSR Dashboard - Offline Deployment Handoff

## Goal
Stand up the CSR Dashboard on a fresh RHEL 9 VM (ideally STIG-hardened, FIPS,
SELinux enforcing, fapolicyd enforcing - to mirror the real air-gapped target)
using the offline bundle workflow. Work through every environment issue, fix
the scripts in place, and document each fix so the changes can be finalized
back into the GitLab repo.

## What this app is
Flask/SQLite certificate request + lifecycle dashboard. Runs behind nginx with
DoD PKI CAC mTLS. gunicorn under systemd as service account `csrapi` on
127.0.0.1:5002. SQLite WAL DB. Production reference instance is
`nipat-pl-rcdn01.eucom.mil`; this handoff is about reproducing a deploy
elsewhere, especially AIR-GAPPED.

## Repo layout (where each file goes)
```
csr-dashboard/
├── VERSION                          # bare version number "1.0.1"
├── README.md
├── .gitignore
├── .gitlab-ci.yml                   # shell-runner lint; PYBIN=python3.9
├── deploy.sh                        # repo -> live paths (perms, fapolicyd, unit validate, restart)
├── gather.sh                        # live -> repo (recovery/baseline only)
├── verify.sh                        # confirm clone == live
├── make-offline-bundle.sh           # builds the air-gap tarball (installer embedded)
├── requirements.txt                 # PINNED pip freeze (see below) - REQUIRED
├── backend/
│   ├── app.py                       -> /opt/csr-dashboard/app.py      root:csrapi 0640
│   ├── notify.py                    -> /opt/csr-dashboard/notify.py   root:csrapi 0640
│   └── import_certs.py              -> /opt/csr-dashboard/import_certs.py
├── frontend/
│   ├── index.html                   -> /var/www/csr/index.html        root:nginx 0640
│   └── app.js                       -> /var/www/csr/app.js
├── helper/
│   ├── csr_dashboard_helper.sh      -> /root/sslcerts/scripts/...      root:root 0750
│   └── csr_dashboard_helper.d/
│       ├── 00-common.sh
│       ├── 10-certtypes.sh
│       └── 20-generate.sh
├── systemd/
│   ├── csr-api.service              -> /etc/systemd/system/  (SINGLE-LINE ExecStart - see note)
│   ├── csr-expiry-warn.service
│   └── csr-expiry-warn.timer
├── nginx/
│   └── 30-csr.conf                  -> /etc/nginx/rcdn01.d/30-csr.conf
├── tools/
│   └── csrbackup.sh                 -> /usr/local/sbin/csrbackup
└── config/
    ├── csr-dashboard.env.example    -> seeds /etc/csr-dashboard/csr-dashboard.env
    └── email.conf.example           -> seeds /etc/csr-dashboard/email.conf
```
NOT tracked / runtime state: the SQLite DB, the venv, the live email.conf,
the live csr-dashboard.env.

## requirements.txt (pinned, from the live venv - python 3.9)
```
blinker==1.9.0
click==8.1.8
flask==3.1.3
gunicorn==23.0.0
importlib-metadata==8.7.1
itsdangerous==2.2.0
jinja2==3.1.6
markupsafe==3.0.3
packaging==26.2
werkzeug==3.1.8
zipp==3.23.1
```
All pure-python wheels (no compiled extensions) - portable across matching
RHEL9/python3.9/x86_64. importlib-metadata + zipp are flask metadata deps on
3.9; they drop on 3.10+.

## Offline workflow the bundle implements
1. On a CONNECTED box matching the target (RHEL9/python3.9/x86_64):
   `./make-offline-bundle.sh`  -> csr-dashboard-offline-1.0.1.tar.gz + .sha256
   (bundles code + wheelhouse/ + requirements.txt + install/ dir + docs)
2. Carry tarball across. On target: `sha256sum -c`, extract.
3. Edit `install/START_HERE` (SMG_HOST, DASHBOARD_URL, FROM_ADDRESS required).
4. `cd install && sudo ./offline-install.sh` - one-shot:
   account, dirs, sudoers, venv (from wheelhouse), configs from START_HERE,
   fapolicyd trust, deploy, start. Prints remaining manual items.
5. Manual (cannot be scripted): PKI/mTLS certs; first-admin bootstrap on fresh DB.

## KNOWN ISSUES FOUND DURING THE LAST OFFLINE ATTEMPT (fix + verify these)
These were hit on a real STIG offline VM. The scripts have attempted fixes;
VALIDATE they actually work end-to-end and refine as needed:

1. **venv directory mode 0700 (CONFIRMED ROOT CAUSE of a long debug).**
   `python -m venv` under root's STIG umask 077 creates /opt/csr-dashboard/venv
   as 0700, so the csrapi GROUP cannot traverse into venv/ to exec gunicorn/
   python. Symptom: "Permission denied" exec-ing venv binaries EVEN WITH
   SELinux + fapolicyd disabled. Diagnose with:
   `namei -l /opt/csr-dashboard/venv/bin/python3`  (look for drwx------ on venv)
   Fix applied in offline-install.sh: chown -R root:csrapi + chmod 0750 the
   venv, venv/bin, and make dirs group-traversable / files group-readable.
   VALIDATE this fully resolves it from a clean run.

2. **fapolicyd trust for the venv.** Fresh venv binaries are unknown to
   fapolicyd; deploy.sh only UPDATES trust for known files. Installer now
   `--file add`s the venv. On the test VM `--file add <dir>` sometimes returned
   "nothing to add" / no list entries - VALIDATE trust actually registers, and
   if `fapolicyd-cli --file add` is unreliable, switch to a rules.d allow:
   `allow perm=execute uid=csrapi : dir=/opt/csr-dashboard/`  (NARROW to the
   specific interpreter path if possible - STIG reviewers dislike broad allows).

3. **systemd unit: single-line ExecStart.** A multi-line ExecStart with
   backslash continuations caused `Missing '='` / `Invalid argument` on unit
   load and the service refused to restart. csr-api.service now uses a SINGLE
   LINE ExecStart. Keep it that way. deploy.sh runs `systemd-analyze verify`
   before reload/restart - confirm that gate fires.

4. **/home/ansible traversal.** csrapi must traverse /home/ansible to reach
   issued/. Installer does `chmod o+x /home/ansible`. There is also a known
   OPEN production bug (not yet fixed): the admin orphan-certs listing 500s
   reading /home/ansible/issued because csrapi can't read the dir - the fix
   is to route that listing through the root helper rather than direct read.
   Note if you see it; it is pre-existing, not caused by the offline deploy.

## ENVIRONMENT THINGS TO PROBE AND DOCUMENT
- Mount options: is /opt or /var noexec? (rcdn01 /opt is NOT noexec; confirm
  the test VM). If noexec, the venv must relocate to an exec-permitted path
  and the systemd ExecStart updated.
- SELinux contexts on /var/www/csr (needs nginx-readable), /opt/csr-dashboard.
  deploy.sh runs restorecon on frontend; confirm contexts are right.
- Does the enclave provide OS packages (python3.9, nginx, sqlite, fapolicyd,
  openssl, policycoreutils, sudo)? Bundle does NOT include OS RPMs.
- PKI: the DoD CA bundle + a server cert for nginx CAC mTLS are site-specific
  and manual. Document exactly what nginx config + cert placement is needed.
- First admin: fresh DB has no admins. Document the csr-bootstrap-admin step
  (binds your CAC DN as the first admin) - that tool was part of original
  setup and may need to be added to the repo/bundle.

## DELIVERABLE BACK
- Any edited scripts (offline-install.sh, deploy.sh, make-offline-bundle.sh,
  systemd units) with the changes that made a clean-VM install succeed.
- A written list of every fix + the exact command/diagnosis, so it can be
  finalized into the repo and the runbook.
- Ideally: the sequence of commands that took a bare RHEL9 VM to a running
  csr-api + nginx serving the dashboard.
