"""Automated certificate renewal.

`run_auto_renew()` is the background pass that closes the certificate lifecycle
loop: an issued cert nearing expiry, whose template opts into auto-renewal, is
re-signed through that template's configured CA backend and recorded as a linked
renewal job (`renewed_from`). It is driven by the `certinel-auto-renew` systemd timer
(via `app.run_auto_renew()`) and by the admin trigger
`POST /api/admin/run-auto-renew`.

Design notes / scope (v1):
  * **Re-sign the stored CSR.** We submit the original job's CSR to the backend
    again, producing a fresh certificate (new serial + validity) for the same
    subject/key. This is provider-agnostic, needs no key material or helper
    access, and runs safely outside a request context (no Flask `g`). The
    renewed cert therefore reuses the original key — key *rotation* on renewal
    (re-key, like the interactive Renew button) is a planned follow-on, gated by
    a future per-template "rekey on renew" option.
  * **Gated three ways.** A global master switch (`auto_renew_enabled`, default
    off), a per-template opt-in (`cert_templates.auto_renew`), and the backend's
    capability/availability. An offline or manual-only deployment never renews.
  * **Idempotent.** Each source job is renewed at most once: we stamp
    `jobs.auto_renewed_at` and skip any job that already has a live renewal
    child. Safe to run on every timer tick.

Returns `(renewed, skipped, errors)`.
"""
import time
import uuid

# Tiers/flags reused from the truthiness convention elsewhere in the app.
_TRUE = ("1", "true", "yes", "on")


def _truthy(v):
    return str(v).strip().lower() in _TRUE if v is not None else False


def _template_renew_cfg(conn, template_id):
    """(auto_renew: bool, window_days: int|None) for a template, or None if the
    template is gone. A NULL/blank window means 'use the global default'."""
    if not template_id:
        return None
    row = conn.execute(
        "SELECT auto_renew, renew_before_days FROM cert_templates WHERE id = ?",
        (template_id,)).fetchone()
    if not row:
        return None
    window = row["renew_before_days"]
    try:
        window = int(window) if window not in (None, "") else None
    except (TypeError, ValueError):
        window = None
    return (bool(row["auto_renew"]), window)


def run_auto_renew():
    """Renew issued certs nearing expiry whose template enables auto-renewal.
    Context-free (no Flask request context) so the systemd timer can call it.
    Returns (renewed, skipped, errors)."""
    import app
    import sign
    import capabilities

    now = time.time()
    if not _truthy(app.get_setting("auto_renew_enabled")):
        return (0, 0, 0)  # master switch off — nothing to do
    if not capabilities.available("lifecycle.auto_renew"):
        return (0, 0, 0)  # commercial feature — not licensed here

    try:
        global_window = int(app.get_setting("auto_renew_before_days") or 30)
    except (TypeError, ValueError):
        global_window = 30
    global_window = max(1, min(global_window, 365))

    # Candidate set: every issued cert expiring within the widest plausible
    # window (cap at a year). Per-job, we then apply the effective window and
    # the template gate. We scan wide and filter narrow so a template with a
    # longer window than the global default still gets picked up.
    horizon = now + 365 * 86400
    with app.db() as conn:
        rows = conn.execute(
            "SELECT id, target_host, csr_pem, template_id, requester_email, "
            "group_id, cert_type, expires_at, auto_renewed_at "
            "FROM jobs WHERE status='issued' AND expires_at IS NOT NULL "
            "AND expires_at > ? AND expires_at <= ? ORDER BY expires_at",
            (now, horizon)).fetchall()

    renewed = skipped = errors = 0
    for r in rows:
        if r["auto_renewed_at"]:
            continue  # already auto-renewed this cert

        with app.db() as conn:
            cfg = _template_renew_cfg(conn, r["template_id"])
        if not cfg or not cfg[0]:
            continue  # no template, or template doesn't opt into auto-renew

        window = cfg[1] or global_window
        if r["expires_at"] > now + window * 86400:
            continue  # not inside the renewal window yet

        # Skip (and stamp) jobs that already have a live renewal, so a manual
        # Renew or a prior pass isn't duplicated.
        with app.db() as conn:
            child = conn.execute(
                "SELECT 1 FROM jobs WHERE renewed_from = ? AND status IN "
                "('pending', 'issued') LIMIT 1", (r["id"],)).fetchone()
        if child:
            _stamp_renewed(app, r["id"], now)
            continue

        policy = app.resolve_signing_policy(r["template_id"])
        backend = (policy.get("signer_backend") or "manual").strip()
        if backend == "manual" or not capabilities.available("ca.signing." + backend):
            skipped += 1  # automated signing unavailable here — leave for a human
            continue

        days_left = int((r["expires_at"] - now) / 86400)
        try:
            result = sign.sign_csr(r["csr_pem"], policy)
        except Exception as e:
            app.log_event("auto_renew", "sign_error", job_id=r["id"],
                          backend=backend, error=str(e)[:200])
            errors += 1
            continue

        # Create the renewal job (a clone of the source, pending) then run it
        # through the shared completion path so it verifies, flips to 'issued',
        # drops the cert, fleet-tracks it, and notifies — exactly like a manual
        # approve-&-sign.
        new_id = uuid.uuid4().hex
        try:
            with app.db() as conn:
                conn.execute(
                    "INSERT INTO jobs (id, created_at, requester_dn, "
                    "requester_serial, requester_ip, requester_email, "
                    "target_host, sans_json, csr_pem, status, has_local_key, "
                    "local_key_name, source, group_id, cert_type, key_algo, "
                    "template_id, renewed_from) "
                    "SELECT ?, ?, requester_dn, requester_serial, requester_ip, "
                    "requester_email, target_host, sans_json, csr_pem, "
                    "'pending', has_local_key, local_key_name, source, "
                    "group_id, cert_type, key_algo, template_id, ? "
                    "FROM jobs WHERE id = ?",
                    (new_id, now, r["id"], r["id"]))
            completed = app._attach_signed_cert(
                new_id, result.cert_pem, actor_dn="system:auto-renew",
                signed_via=backend, log_action="auto_renew")
        except app.CompletionError as e:
            app.log_event("auto_renew", "complete_error", job_id=new_id,
                          source_job=r["id"], error=str(e.payload)[:200])
            errors += 1
            continue
        except Exception as e:
            app.log_event("auto_renew", "error", job_id=r["id"],
                          error=str(e)[:200])
            errors += 1
            continue

        _stamp_renewed(app, r["id"], now)
        app.log_event("auto_renew", "renewed", job_id=r["id"], new_job_id=new_id,
                      target=r["target_host"], backend=backend,
                      days_left=days_left)
        app.fire_webhooks("job.renewed", {
            "job_id": new_id, "renewed_from": r["id"],
            "target_host": r["target_host"],
            "requester_email": r["requester_email"],
            "group_id": r["group_id"], "backend": backend,
            "days_left": days_left,
            "expires_at": completed.get("expires_at"),
        })
        renewed += 1

    return (renewed, skipped, errors)


def _stamp_renewed(app, job_id, when):
    """Mark a source job as auto-renewed so it isn't reconsidered."""
    try:
        with app.db() as conn:
            conn.execute("UPDATE jobs SET auto_renewed_at = ? WHERE id = ?",
                         (when, job_id))
    except Exception:
        pass  # best-effort; a re-scan is guarded by the renewal-child check too
