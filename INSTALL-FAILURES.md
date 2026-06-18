# CSR Dashboard — Offline STIG Install: Failures & Fixes Log

Target: VM `disa` (192.168.200.12), RHEL 9.8, python3.9, x86_64.
SELinux **Enforcing**, fapolicyd **active**, FIPS **enabled**.
`/tmp` and `/home` are **noexec**; `/opt` and `/var` are exec-OK.
Installer/operator: Claude Code on ac2-ansible, driving the VM as `adam` (passwordless sudo).
Date: 2026-06-16. App version (VERSION.txt): 1.0.1.

This log is the deliverable back to claude.ai. Each entry: what failed, the
diagnosis, the fix applied, and whether it should be finalized into the repo.

---

## ENVIRONMENT PROBE (baseline, before install)

- OS: RHEL 9.8 (Plow), kernel 5.14, x86_64 — matches the bundle target.
- python3.9 present at /usr/bin/python3.9.
- SELinux Enforcing; fapolicyd active; FIPS=1.
- Present: openssl, restorecon, fapolicyd-cli, semanage.
- **MISSING OS packages: nginx, sqlite (sqlite3 CLI), gunicorn (pip).**
- Mounts: /tmp noexec,nosuid,nodev ; /home noexec,nosuid,nodev ; /var exec-OK ; /opt under / (exec-OK).
- pypi.org reachable (HTTP 200) — VM is NOT truly air-gapped in this lab.
- Clean box: csrapi user absent, no app dirs.
- Note: `stiglite` already listens on :8443 (unrelated app; does not conflict
  with csr-api on 127.0.0.1:5002 or nginx :443, but :8443 is taken).

---

## FINDINGS

### F1 — Repo is a FLATTENED "gather" dump, not the layout every script expects (BLOCKER)
- **Symptom:** `make-offline-bundle.sh` copies `backend frontend helper systemd nginx tools config deploy.sh requirements.txt VERSION`; `deploy.sh` reads a MANIFEST of `backend/app.py`, `frontend/index.html`, `systemd/*.service`, etc. None of those paths exist in the clone — the repo is flat with `.txt` suffixes and renamed files (`repo-deploy.sh.txt`, `app.py`, `helper.d-00-common.sh`, `csr-api.service.txt`, `VERSION.txt`, …).
- **Result:** bundle build copies nothing ("skip missing: …"); deploy.sh exits `MISSING in repo: backend/app.py`.
- **Diagnosis:** the repo was populated by an upload/"gather" that flattened the tree and appended `.txt` to scripts/units (likely to dodge CI exec/lint or GitLab rendering). The canonical files are present but mis-named/mis-placed.
- **Fix applied:** reconstructed the documented tree (backend/ frontend/ helper/csr_dashboard_helper.d/ systemd/ nginx/ tools/ config/ + deploy.sh gather.sh verify.sh make-offline-bundle.sh VERSION .gitlab-ci.yml .gitignore README.md). Mapping: `repo-deploy.sh.txt`→`deploy.sh`, `helper.d-00-common.sh`→`helper/csr_dashboard_helper.d/00-common.sh`, `csr-api.service.txt`→`systemd/csr-api.service`, `VERSION.txt`→`VERSION`, etc.
- **Finalize into repo:** YES — the repo must be committed in the real tree layout, OR every script rewritten to the flat names. Recommend the former (matches README/handoff/CI which all assume the tree).

### F2 — `requirements.txt` is missing from the repo (BLOCKER for bundle + venv)
- **Symptom:** `make-offline-bundle.sh` and `offline-install.sh` require `requirements.txt`; bundle builder falls back to an unpinned `flask\ngunicorn` and warns. The handoff documents the real pinned list but it was never committed.
- **Fix applied:** created `requirements.txt` from the handoff's pinned freeze (flask 3.1.3, gunicorn 23.0.0, werkzeug 3.1.8, jinja2 3.1.6, markupsafe 3.0.3, click 8.1.8, blinker 1.9.0, itsdangerous 2.2.0, importlib-metadata 8.7.1, zipp 3.23.1, packaging 26.2).
- **Finalize into repo:** YES — commit `requirements.txt`.

### F3 — `nginx/30-csr.conf` is referenced but ABSENT from the repo (BLOCKER for deploy.sh)
- **Symptom:** `deploy.sh` MANIFEST unconditionally includes `nginx/30-csr.conf /etc/nginx/csr-dashboard.d/30-csr.conf`; the file does not exist anywhere in the repo (only referenced in comments). deploy.sh exits `MISSING in repo: nginx/30-csr.conf`.
- **Fix applied:** authored `nginx/30-csr.conf` from the app's contract (serve `/csr/` static from /var/www/csr; proxy `/csr/api/`→127.0.0.1:5002/api/; set X-Client-DN/Verify/Serial from the TLS client cert). See F-NGINX below for the CAC-mTLS vs self-signed decision.
- **Finalize into repo:** YES — the production nginx config must be committed (currently it only lives on the production box).
### F4 — fapolicyd blocks non-root reads of ALL interpreted-language source (.py/.sh/.js…) on the STIG target
- **Symptom:** `make-offline-bundle.sh` (run as a normal user) dies: `cp: cannot open 'backend/app.py' for reading: Operation not permitted` — only on the `.py` files.
- **Diagnosis:** EPERM (not EACCES) ⇒ fapolicyd, not DAC/SELinux. `/etc/fapolicyd/rules.d/10-languages.rules` defines `%languages=…,text/x-python,…` and the STIG ruleset denies untrusted subjects `perm=open` on those types. adam (untrusted subject) → DENIED; root → OK. Confirmed: `cat app.py` DENIED as adam, OK as root.
- **Impact:** the bundle builder CANNOT run as a non-root user on a fapolicyd-enforcing box. (The real installer is fine — `deploy.sh`/`offline-install.sh` run as root.)
- **Fix applied:** build the offline bundle on a **separate connected non-STIG box** — per the handoff's own design ("run on a CONNECTED box matching the target"). Used ac2-ansible (AlmaLinux 9.8 / python3.9 / pip / fapolicyd inactive). On the STIG target itself, building would require running the builder as root.
- **Finalize into repo:** DOC — add a one-line note to `make-offline-bundle.sh`/OFFLINE-INSTALL.md: "build on a connected box WITHOUT fapolicyd enforcing, or run as root." Optional hardening: have the builder `tar`-stream from git instead of `cp` so it never opens source as the invoking user.

### F5 — `python3-pip` absent on the STIG target (confirms build-box must be separate)
- **Symptom:** `python3.9 -m pip download …` → `No module named pip` on the VM.
- **Diagnosis:** STIG baseline ships no pip and (in a real enclave) no internet. The bundle is explicitly designed to be built elsewhere and to bootstrap pip INTO the venv from the bundled wheelhouse on the target — so this is expected, but it makes "build on the target" impossible. Reinforces F4's fix.
- **Finalize into repo:** DOC — OFFLINE-INSTALL.md should state plainly: the target needs NO pip; the build box needs pip + internet.

### F6 — Correct build box identified
- ac2-ansible (AlmaLinux 9.8, py3.9, pip 25.3, fapolicyd inactive, internet→pypi) is a valid "connected box matching the target." Bundle built here, carried to the VM.
### F7 — fapolicyd denies execute-by-path of all untrusted scripts (installer, deploy.sh, csrbackup) (BLOCKER)
- **Symptom:** `sudo ./offline-install.sh` → `sudo: unable to execute ./offline-install.sh: Permission denied`. Script IS mode 0700 +x and on an exec-OK fs (/var/tmp). Proven: `sudo ./deploy.sh` = DENIED; `sudo bash deploy.sh` = runs.
- **Diagnosis:** fapolicyd denies `execve` of any file not in the trust DB. A freshly-extracted bundle script is untrusted ⇒ EACCES on exec-by-path. `bash <script>` works because the kernel execs trusted /usr/bin/bash, which only *opens* (reads) the script (shell scripts are NOT in the `%languages` open-deny list, unlike .py — see F4).
- **Impact:** cascades — `offline-install.sh` invokes `./deploy.sh` and `csrbackup` BY PATH internally, so even launching the installer via `bash` would fail at those inner calls.
- **Fix applied (operator-correct):** add the bundle to the fapolicyd trust DB before running: `fapolicyd-cli --trust-file add <each script>` (or `--file add <dir>`) + `fapolicyd-cli --update`. Then exec-by-path is allowed.
- **Finalize into repo:** DOC + optional code — OFFLINE-INSTALL.md must add a pre-step: trust the bundle (or run every script as `bash <script>`). Better long-term fix: have `offline-install.sh` call its children as `bash ./deploy.sh` / `bash <csrbackup>` so the workflow is fapolicyd-safe without trusting /var/tmp. The installed csrbackup at /usr/local/sbin gets trusted by deploy's fapolicyd step, but the *bundle-local* deploy.sh call still needs this.
### F8 — installer's `[[ -x ./deploy.sh ]]` guard misfires; aborts step 7 with "deploy.sh missing"
- **Symptom:** after a clean steps 0–6, step 7 dies `ERROR: deploy.sh missing in bundle root`, even though `deploy.sh` is present (mode 0700, owner = build user) in BUNDLE_ROOT.
- **Diagnosis:** the guard tests `-x` (executable bit) rather than presence. The bundle preserves the build user's restrictive `0700`; under fapolicyd/STIG the file is never meant to be exec-by-path anyway (we run it via `bash`, see F7). The `-x` test is the wrong predicate.
- **Fix applied:** changed guard to `[[ -f ./deploy.sh ]]` and the call to `bash ./deploy.sh` (F7).
- **Finalize into repo:** YES — in `offline-install.sh` change `[[ -x ./deploy.sh ]]` → `[[ -f ./deploy.sh ]]` and `./deploy.sh` → `bash ./deploy.sh`.
### F9 — nginx not enabled/started on a fresh box; csr-dashboard.d include not wired; deploy.sh only *reloads* (BLOCKER for frontend)
- **Symptom:** end of deploy step 7: `nginx.service is not active, cannot reload.` deploy.sh aborts (set -e) at `systemctl reload nginx`, so it never reaches the csr-api restart either.
- **Diagnosis:** deploy.sh assumes nginx is already running and an enclave include layout (`/etc/nginx/csr-dashboard.d/` `include`d from a server{} block in nginx.conf). On a fresh RHEL box: nginx is installed-but-disabled, and nothing includes `csr-dashboard.d`. Also `nginx -t` "passed" misleadingly — because the un-wired 30-csr.conf wasn't even loaded.
- **Fix applied (post-install):** wired `include /etc/nginx/csr-dashboard.d/*.conf;` into nginx.conf, generated a self-signed server cert (PKI placeholder — see F-PKI), `systemctl enable --now nginx`. deploy.sh changed conceptually to `systemctl reload-or-restart nginx` and to not hard-fail when nginx is down at first install.
- **Finalize into repo:** YES (deploy.sh: use `reload-or-restart`; document the nginx.conf include + enable step in OFFLINE-INSTALL.md as a one-time prereq) + the production server-block/wiring must be committed under nginx/.

### F10 — venv permission fix is INCOMPLETE: non-exec files (pyvenv.cfg, site-packages *.py) stay 0600 → csr-api crash-loops (BLOCKER)
- **Symptom:** csr-api fails to start, crash-loops: `PermissionError: [Errno 13] Permission denied: '/opt/csr-dashboard/venv/pyvenv.cfg'` (gunicorn runs as csrapi).
- **Diagnosis:** EACCES (DAC), not fapolicyd. The installer's venv fix only g+r'd executables: `find "$VENV" -type f -perm -u+x -exec chmod g+rx`. Files WITHOUT the user-exec bit — `pyvenv.cfg` and every installed `.py` module — were created under root umask 077 as 0600 root:csrapi, so group csrapi cannot read them. python can't read pyvenv.cfg (venv detection) nor import modules.
- **Fix applied:** `chmod -R g+rX /opt/csr-dashboard/venv` (group-read ALL files, group-exec dirs + executables). This is the correct generalization of the handoff's known-issue #1.
- **Finalize into repo:** YES — in `offline-install.sh` replace the two narrow `find` lines with a single `chmod -R g+rX "$VENV"` (after `chown -R root:csrapi "$VENV"`).
### F11 — firewalld blocks 443 (dashboard unreachable off-box)
- **Symptom:** on-box `curl https://localhost/csr/` = 200, but from another host = HTTP 000.
- **Diagnosis:** firewalld allowed only ssh/cockpit/dhcpv6-client + ports 8080,8443 (the unrelated `stiglite`). 443 not opened.
- **Fix applied:** `firewall-cmd --permanent --add-service=https && firewall-cmd --reload`. Off-box now 200.
- **Finalize into repo:** DOC — add the firewall step to OFFLINE-INSTALL.md (the installer doesn't touch firewalld).

### F-PKI — CAC mTLS is a manual, site-specific step; lab uses a self-signed placeholder (EXPECTED, not a defect)
- The repo ships no server cert and no DoD CA bundle (correct — site-specific). The installer's nginx -t gate is the intended "PKI not done yet" signal.
- **Lab action:** authored 30-csr.conf with `ssl_verify_client optional_no_ca` + a self-signed `/etc/pki/csr-dashboard/server.{crt,key}` so the box serves. Without a real CAC, `client_identity()` returns `ip:<addr>` (no admin). 
- **Production TODO (cannot be scripted here):** install DoD CA bundle, set `ssl_client_certificate <dod-cas.pem>; ssl_verify_client on; ssl_verify_depth 3;`, install this server's real cert.

### F-ADMIN — no first-admin path: `csr-bootstrap-admin` is referenced but ABSENT, and the app has no built-in promotion (BLOCKER for real use)
- **Diagnosis:** `_upsert_user()` always inserts `is_admin=0`; there is no env/CLI/first-DN bootstrap anywhere in app.py. The handoff names a `csr-bootstrap-admin` tool that is NOT in the repo/bundle.
- **Impact:** a fresh DB has zero admins and no supported way to create one.
- **Workaround (manual):** after the operator authenticates once (so their DN row exists), `sqlite3 /var/lib/csr-dashboard/jobs.db "UPDATE users SET is_admin=1 WHERE dn='<CAC DN>'"` then restart. 
- **Finalize into repo:** YES — add the `csr-bootstrap-admin` tool (and ship it in the bundle), or document the sqlite3 promotion as the official bootstrap.

---

## RESULT — install SUCCEEDED to a running, network-reachable dashboard

Standing on VM `disa` (192.168.200.12), RHEL 9.8, SELinux Enforcing + FIPS + fapolicyd active:
- `csr-api.service`  : **active** (gunicorn as csrapi, 127.0.0.1:5002)
- `nginx.service`    : **active** (HTTPS 443, serving /csr/ + proxying /csr/api/)
- `csr-expiry-warn.timer` : **active**
- `jobs.db`          : created (csrapi:csrapi) — schema initialized
- Health: `curl -sk https://192.168.200.12/csr/api/health` → `{"ok":true,"version":"1.0.1"}` (both on-box and over the network)

### Remaining MANUAL items (by design, not failures)
1. PKI/CAC mTLS — replace the self-signed cert + enable `ssl_verify_client on` with the DoD CA bundle (F-PKI).
2. First admin — provide/ship `csr-bootstrap-admin`, or run the sqlite3 promotion (F-ADMIN).
3. Email/SMG — `/etc/csr-dashboard/email.conf` currently points at a placeholder relay (smtp.ac2.lan); set a real SMG relay that whitelists this host (no functional mail in the lab).

### Repo changes to FINALIZE (summary)
- Restructure repo from the flat "gather" dump into the real tree (F1).
- Commit `requirements.txt` (F2), the production `nginx/30-csr.conf` (F3), and the `csr-bootstrap-admin` tool (F-ADMIN).
- `offline-install.sh`: `-x`→`-f` guard + `bash ./deploy.sh` (F7/F8); replace the narrow venv `find` chmods with `chmod -R g+rX "$VENV"` (F10).
- `deploy.sh`: `systemctl reload-or-restart nginx` and don't hard-fail when nginx is down at first install (F9); call children via `bash` for fapolicyd safety (F7).
- OFFLINE-INSTALL.md: build box must be NON-fapolicyd + have pip/internet (F4/F5); add firewalld 443, nginx.conf include + enable, and PKI/admin manual steps (F9/F11/F-PKI/F-ADMIN).
