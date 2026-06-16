#!/usr/bin/env python3
"""import_certs.py - import fleet-scanned certificates into the CSR Dashboard.

Reads a JSON file produced by the fleet-cert-scan playbook:
    [{"host": "nipat-pl-web01.eucom.mil",
      "path": "/etc/pki/tls/certs/web01.crt",
      "pem":  "-----BEGIN CERTIFICATE-----..."},
     ...]

For each record, parses the FIRST certificate block in the file (the leaf,
in a typical chain bundle), extracts metadata via openssl, and upserts into
the fleet_certs table keyed on (host, path). If the fingerprint at a path
changed since the last run (cert was renewed on-host), the expiry-warning
tier is reset so warnings re-arm for the new cert. CA certificates
(basicConstraints CA:TRUE) are skipped by default.

Run as the csrapi user (the DB owner):
    sudo -u csrapi python3 /opt/csr-dashboard/import_certs.py /tmp/fleet-certs.json

Stdlib only - no Flask/venv required, though running under the venv python
is also fine.
"""

import argparse
import calendar
import json
import re
import sqlite3
import subprocess
import sys
import time

DB_PATH = "/var/lib/csr-dashboard/jobs.db"

EKU_TYPE_MAP = {
    "TLS Web Server Authentication": "web",
    "TLS Web Client Authentication": "client",
    "E-mail Protection": "email",
    "Code Signing": "codesign",
    "OCSP Signing": "ocsp",
    "Time Stamping": "timestamp",
    "ipsec Internet Key Exchange": "ipsec",
    "1.3.6.1.5.5.7.3.14": "8021x",  # id-kp-eapOverLAN
}

PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def openssl(args, pem):
    proc = subprocess.run(["openssl", "x509", "-noout"] + args,
                          input=pem, capture_output=True, text=True, timeout=15)
    return proc.returncode, proc.stdout, proc.stderr


def parse_date(line, prefix):
    if not line.startswith(prefix):
        return None
    try:
        ts = time.strptime(line[len(prefix):].strip(), "%b %d %H:%M:%S %Y %Z")
        return float(calendar.timegm(ts))
    except ValueError:
        return None


def parse_cert(pem):
    """Extract metadata from the first cert block. Returns dict or None."""
    m = PEM_BLOCK_RE.search(pem)
    if not m:
        return None
    pem = m.group(0) + "\n"

    rc, out, _ = openssl(
        ["-subject", "-issuer", "-serial", "-startdate", "-enddate",
         "-fingerprint", "-sha256", "-nameopt", "RFC2253"], pem)
    if rc != 0:
        return None

    info = {"pem": pem, "cn": None, "issuer": None, "serial": None,
            "not_before": None, "expires_at": None, "fingerprint": None,
            "sans": [], "cert_types": [], "is_ca": False}

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            cm = re.search(r"CN=([^,]+)", line)
            info["cn"] = cm.group(1).strip() if cm else line[len("subject="):][:120]
        elif line.startswith("issuer="):
            im = re.search(r"CN=([^,]+)", line)
            info["issuer"] = (im.group(1).strip() if im
                              else line[len("issuer="):][:120])
        elif line.startswith("serial="):
            info["serial"] = line[len("serial="):].strip()[:64]
        elif line.startswith("notBefore="):
            info["not_before"] = parse_date(line, "notBefore=")
        elif line.startswith("notAfter="):
            info["expires_at"] = parse_date(line, "notAfter=")
        elif "Fingerprint=" in line:
            info["fingerprint"] = line.split("Fingerprint=", 1)[1].replace(":", "").lower()

    # Extensions: SANs, EKU, basicConstraints
    rc, out, _ = openssl(["-text", "-certopt", "no_pubkey,no_sigdump"], pem)
    if rc == 0:
        sm = re.search(r"Subject Alternative Name:\s*\n\s*(.+)", out)
        if sm:
            for tok in sm.group(1).split(","):
                tok = tok.strip()
                if tok.startswith(("DNS:", "IP Address:", "email:")):
                    info["sans"].append(tok.split(":", 1)[1].strip())
        em = re.search(r"Extended Key Usage:\s*(critical)?\s*\n\s*(.+)", out)
        if em:
            for tok in em.group(2).split(","):
                t = EKU_TYPE_MAP.get(tok.strip())
                if t and t not in info["cert_types"]:
                    info["cert_types"].append(t)
        if re.search(r"CA:\s*TRUE", out):
            info["is_ca"] = True

    return info


def main():
    ap = argparse.ArgumentParser(description="Import fleet certs into the CSR Dashboard")
    ap.add_argument("json_file", help="JSON array of {host, path, pem}")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--default-notify-email", default="",
                    help="notify_email applied to NEW records (existing records keep theirs)")
    ap.add_argument("--include-ca-certs", action="store_true",
                    help="also import CA certificates (skipped by default)")
    ap.add_argument("--prune-host", action="append", default=[],
                    metavar="HOST",
                    help="after import, delete records for HOST whose path was "
                         "not seen in this run (repeatable)")
    args = ap.parse_args()

    with open(args.json_file) as f:
        records = json.load(f)
    if not isinstance(records, list):
        print("ERROR: input must be a JSON array", file=sys.stderr)
        return 2

    conn = sqlite3.connect(args.db, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")

    now = time.time()
    added = updated = renewed = skipped_ca = skipped_bad = mismatches = 0
    seen_paths = {}  # host -> set(paths)

    for rec in records:
        host = (rec.get("host") or "").strip()
        path = (rec.get("path") or "").strip()
        pem = rec.get("pem") or ""
        if not host or not path or "BEGIN CERTIFICATE" not in pem:
            skipped_bad += 1
            continue
        info = parse_cert(pem)
        if not info or not info["fingerprint"]:
            skipped_bad += 1
            print(f"SKIP (unparseable): {host}:{path}", file=sys.stderr)
            continue
        if info["is_ca"] and not args.include_ca_certs:
            skipped_ca += 1
            continue

        # Filename-vs-content sanity check: files named <fqdn>.crt should
        # contain a cert whose CN or SANs include that fqdn. A mismatch
        # usually means the wrong cert was dropped at that path.
        base = re.sub(r"\.(crt|cer|pem)$", "", path.rsplit("/", 1)[-1], flags=re.I)
        if "." in base:  # looks like an fqdn, not a generic name
            names = {(info["cn"] or "").lower()} | {s.lower() for s in info["sans"]}
            if base.lower() not in names:
                mismatches += 1
                print(f"MISMATCH: {host}:{path} is named '{base}' but the cert "
                      f"inside is CN={info['cn']!r} SANs={info['sans']}",
                      file=sys.stderr)

        seen_paths.setdefault(host, set()).add(path)
        existing = conn.execute(
            "SELECT id, fingerprint FROM fleet_certs WHERE host=? AND path=?",
            (host, path)).fetchone()

        if existing is None:
            conn.execute("""
                INSERT INTO fleet_certs (host, path, fingerprint, cn, sans_json,
                    issuer, serial, not_before, expires_at, cert_types,
                    notify_email, first_seen, last_seen, expiry_warned, pem)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """, (host, path, info["fingerprint"], info["cn"],
                  json.dumps(info["sans"]), info["issuer"], info["serial"],
                  info["not_before"], info["expires_at"],
                  ",".join(sorted(info["cert_types"])) or None,
                  args.default_notify_email or None, now, now, info["pem"]))
            added += 1
        else:
            cert_changed = existing["fingerprint"] != info["fingerprint"]
            conn.execute("""
                UPDATE fleet_certs SET fingerprint=?, cn=?, sans_json=?,
                    issuer=?, serial=?, not_before=?, expires_at=?,
                    cert_types=?, last_seen=?,
                    expiry_warned = CASE WHEN ? THEN 0 ELSE expiry_warned END,
                    pem=?
                WHERE id=?
            """, (info["fingerprint"], info["cn"], json.dumps(info["sans"]),
                  info["issuer"], info["serial"], info["not_before"],
                  info["expires_at"],
                  ",".join(sorted(info["cert_types"])) or None,
                  now, 1 if cert_changed else 0, info["pem"], existing["id"]))
            if cert_changed:
                renewed += 1
            else:
                updated += 1

    pruned = 0
    for host in args.prune_host:
        paths = seen_paths.get(host, set())
        rows = conn.execute(
            "SELECT id, path FROM fleet_certs WHERE host=?", (host,)).fetchall()
        for r in rows:
            if r["path"] not in paths:
                conn.execute("DELETE FROM fleet_certs WHERE id=?", (r["id"],))
                pruned += 1

    conn.commit()
    conn.close()
    print(f"import: added={added} updated={updated} renewed={renewed} "
          f"skipped_ca={skipped_ca} skipped_bad={skipped_bad} pruned={pruned} "
          f"name_mismatches={mismatches}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
