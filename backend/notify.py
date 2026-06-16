"""Email notifications for the CSR Dashboard.

Plain SMTP over port 25 to an IP-whitelisted relay (e.g., DoD SMG).
No STARTTLS, no SSL, no authentication.

Reads config from /etc/csr-dashboard/email.conf at import time. All
public functions return (ok, reason) and never raise; SMTP failures
must never break the calling endpoint.

Three event functions, each accepting an optional group_email so team
distribution lists get a copy when a job is assigned to a group:
    send_cert_issued(job, uploader_dn, group_email=None)
    send_cancelled(job, canceller_dn, reason, group_email=None)
    send_failed(job, marker_dn, error, group_email=None)

Recipient resolution:
    requester_email set, group email set, different    -> To: requester, Cc: group
    requester_email set, no group email                -> To: requester
    no requester_email, group email set                -> To: group
    neither set                                         -> skipped (False, "no recipient")
Plus the static Cc list from email.conf [recipients] cc, deduplicated.
"""
import base64
import configparser
import smtplib
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path

CONFIG_PATH = Path("/etc/csr-dashboard/email.conf")

# Selectable delivery methods. The admin picks ONE in the UI ([method]
# provider); only that provider's settings are validated/used, the others
# lie dormant in the file so switching back is lossless.
VALID_PROVIDERS = ("smg", "smtp", "mailgun")

_config = None
_enabled = False
_disabled_reason = "not initialized"


def _provider_of(cfg):
    p = cfg.get("method", "provider", fallback="smg").strip().lower()
    return p if p in VALID_PROVIDERS else "smg"


def _load_config():
    global _config, _enabled, _disabled_reason

    if not CONFIG_PATH.exists():
        _enabled = False
        _disabled_reason = f"{CONFIG_PATH} not found"
        return

    cfg = configparser.ConfigParser()
    try:
        cfg.read(CONFIG_PATH)
    except configparser.Error as e:
        _enabled = False
        _disabled_reason = f"config parse error: {e}"
        return

    provider = _provider_of(cfg)
    from_addr = cfg.get("from", "address", fallback="").strip()
    if not from_addr or from_addr.startswith("REPLACE"):
        _enabled = False
        _disabled_reason = "from address is empty or placeholder"
        return

    # Only the SELECTED provider's required fields gate enablement.
    if provider in ("smg", "smtp"):
        host = cfg.get("smtp", "host", fallback="").strip()
        if not host or host.startswith("REPLACE"):
            _enabled = False
            _disabled_reason = f"[{provider}] smtp host is empty or placeholder"
            return
    elif provider == "mailgun":
        api_key = cfg.get("mailgun", "api_key", fallback="").strip()
        domain = cfg.get("mailgun", "domain", fallback="").strip()
        if not api_key or api_key.startswith("REPLACE"):
            _enabled = False
            _disabled_reason = "[mailgun] api_key is empty or placeholder"
            return
        if not domain or domain.startswith("REPLACE"):
            _enabled = False
            _disabled_reason = "[mailgun] domain is empty or placeholder"
            return

    _config = cfg
    _enabled = True
    _disabled_reason = ""


_load_config()


def is_enabled():
    return _enabled


def disabled_reason():
    return _disabled_reason


def _cn_from_dn(dn):
    """Pull CN out of a subject DN for friendlier display in email bodies."""
    if not dn:
        return "(unknown)"
    if "CN=" not in dn:
        return dn
    try:
        return dn.split("CN=", 1)[1].split(",", 1)[0].strip()
    except Exception:
        return dn


def _send_message(msg, recipients):
    """Low-level send. Dispatches to the configured provider. Raises on any
    failure; callers catch (smtplib.SMTPException, socket.error, OSError) and
    the mailgun path raises OSError on a non-2xx / unreachable API."""
    provider = _provider_of(_config)
    if provider == "mailgun":
        _send_mailgun(msg)
    elif provider == "smtp":
        _send_smtp(msg, recipients)
    else:
        _send_smg(msg, recipients)


def _send_smg(msg, recipients):
    """SMG / plain relay: SMTP on :25, no TLS, no auth (IP-whitelisted)."""
    host = _config.get("smtp", "host").strip()
    port = _config.getint("smtp", "port", fallback=25)
    timeout = _config.getint("smtp", "timeout", fallback=10)
    with smtplib.SMTP(host, port, timeout=timeout) as s:
        s.ehlo()
        s.send_message(msg, to_addrs=recipients)


def _send_smtp(msg, recipients):
    """Standard SMTP with optional STARTTLS / implicit-SSL and auth."""
    host = _config.get("smtp", "host").strip()
    port = _config.getint("smtp", "port", fallback=587)
    timeout = _config.getint("smtp", "timeout", fallback=10)
    security = _config.get("smtp", "security", fallback="starttls").strip().lower()
    username = _config.get("smtp", "username", fallback="").strip()
    password = _config.get("smtp", "password", fallback="")

    if security == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=timeout,
                              context=ssl.create_default_context()) as s:
            s.ehlo()
            if username:
                s.login(username, password)
            s.send_message(msg, to_addrs=recipients)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as s:
            s.ehlo()
            if security == "starttls":
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            if username:
                s.login(username, password)
            s.send_message(msg, to_addrs=recipients)


def _send_mailgun(msg):
    """Send via the Mailgun HTTP API. Recipients are taken from the message
    To/Cc headers (every send path sets To). Raises OSError on non-2xx."""
    api_key = _config.get("mailgun", "api_key").strip()
    domain = _config.get("mailgun", "domain").strip()
    base = _config.get("mailgun", "base_url",
                       fallback="https://api.mailgun.net").strip().rstrip("/")
    timeout = _config.getint("smtp", "timeout", fallback=20)

    fields = [
        ("from", msg["From"]),
        ("subject", msg["Subject"] or ""),
        ("text", msg.get_content()),
    ]
    for r in [a.strip() for a in (msg["To"] or "").split(",") if a.strip()]:
        fields.append(("to", r))
    if msg["Cc"]:
        for c in [a.strip() for a in msg["Cc"].split(",") if a.strip()]:
            fields.append(("cc", c))
    for h in ("X-CSR-Dashboard-Event", "X-CSR-Dashboard-Job-Id"):
        if msg[h]:
            fields.append((f"h:{h}", msg[h]))

    data = urllib.parse.urlencode(fields).encode("utf-8")
    token = base64.b64encode(f"api:{api_key}".encode()).decode()
    req = urllib.request.Request(
        f"{base}/v3/{domain}/messages", data=data, method="POST",
        headers={"Authorization": f"Basic {token}",
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if not (200 <= resp.status < 300):
                raise OSError(f"mailgun HTTP {resp.status}")
            resp.read(512)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(300).decode("utf-8", "replace")
        except Exception:
            pass
        raise OSError(f"mailgun HTTP {e.code}: {body or e.reason}")
    except urllib.error.URLError as e:
        raise OSError(f"mailgun unreachable: {e.reason}")


def _resolve_recipients(job, group_email):
    """Determine To and Cc based on job's requester_email and an optional
    group distribution list address. Returns (to_addr, [cc...])."""
    req = (job.get("requester_email") or "").strip()
    grp = (group_email or "").strip() if group_email else ""
    if req and grp and req.lower() != grp.lower():
        return req, [grp]
    if req:
        return req, []
    if grp:
        return grp, []
    return None, []


def _compose_and_send(*, subject, body, to_addr, cc_addrs, event_tag, job_id):
    """Compose an EmailMessage and dispatch. Returns (ok, reason)."""
    if not _enabled:
        return False, f"notifications disabled ({_disabled_reason})"
    if not to_addr:
        return False, "no recipient"

    try:
        from_addr = _config.get("from", "address").strip()
        config_cc_raw = _config.get("recipients", "cc", fallback="").strip()
    except configparser.Error as e:
        return False, f"config read error: {e}"

    config_cc = ([a.strip() for a in config_cc_raw.split(",") if a.strip()]
                 if config_cc_raw else [])

    # Combine caller Cc and config Cc, deduplicated against To and each other
    cc_final = []
    seen = {to_addr.lower()}
    for addr in list(cc_addrs or []) + config_cc:
        a = (addr or "").strip()
        if a and a.lower() not in seen:
            cc_final.append(a)
            seen.add(a.lower())

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    if cc_final:
        msg["Cc"] = ", ".join(cc_final)
    msg["Subject"] = subject
    msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-CSR-Dashboard-Event"] = event_tag
    msg["X-CSR-Dashboard-Job-Id"] = job_id
    msg.set_content(body)

    recipients = [to_addr] + cc_final
    try:
        _send_message(msg, recipients)
        return True, "sent"
    except (smtplib.SMTPException, socket.error, OSError) as e:
        return False, f"{type(e).__name__}: {str(e)[:160]}"


def _dashboard_url():
    return _config.get(
        "content", "dashboard_url",
        fallback="https://nipat-pl-rcdn01.eucom.mil/csr/",
    ).strip()


def _utc_now():
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())


def send_cert_issued(job, uploader_dn, group_email=None):
    """Notify when a signed certificate has been uploaded for a CSR."""
    to_addr, cc = _resolve_recipients(job, group_email)
    if not to_addr:
        return False, "no recipient (no requester_email and no group_email)"

    target = job.get("target_host", "(unknown)")
    job_id = job.get("id", "(unknown)")
    uploader_cn = _cn_from_dn(uploader_dn)

    subject = f"[CSR Dashboard] Certificate issued for {target}"
    body = (
        "A signed certificate has been uploaded for your CSR request.\n"
        "\n"
        f"Target host:  {target}\n"
        f"Job ID:       {job_id}\n"
        f"Uploaded by:  {uploader_cn}\n"
        f"Timestamp:    {_utc_now()}\n"
        "\n"
        "View the job and download the certificate:\n"
        f"  {_dashboard_url()}\n"
        "\n"
        "This is an automated message from the CSR Dashboard at\n"
        "nipat-pl-rcdn01.eucom.mil. Do not reply to this address.\n"
    )
    return _compose_and_send(
        subject=subject, body=body,
        to_addr=to_addr, cc_addrs=cc,
        event_tag="cert_issued", job_id=job_id,
    )


def send_cancelled(job, canceller_dn, reason, group_email=None):
    """Notify when a CSR request has been cancelled."""
    to_addr, cc = _resolve_recipients(job, group_email)
    if not to_addr:
        return False, "no recipient (no requester_email and no group_email)"

    target = job.get("target_host", "(unknown)")
    job_id = job.get("id", "(unknown)")
    canceller_cn = _cn_from_dn(canceller_dn)
    reason_text = (reason or "").strip() or "(no reason given)"

    subject = f"[CSR Dashboard] Request cancelled for {target}"
    body = (
        "A CSR request has been cancelled.\n"
        "\n"
        f"Target host:  {target}\n"
        f"Job ID:       {job_id}\n"
        f"Cancelled by: {canceller_cn}\n"
        f"Reason:       {reason_text}\n"
        f"Timestamp:    {_utc_now()}\n"
        "\n"
        "View the job in the dashboard:\n"
        f"  {_dashboard_url()}\n"
        "\n"
        "This is an automated message from the CSR Dashboard at\n"
        "nipat-pl-rcdn01.eucom.mil. Do not reply to this address.\n"
    )
    return _compose_and_send(
        subject=subject, body=body,
        to_addr=to_addr, cc_addrs=cc,
        event_tag="cancelled", job_id=job_id,
    )


def send_failed(job, marker_dn, error, group_email=None):
    """Notify when a CSR request has been marked failed."""
    to_addr, cc = _resolve_recipients(job, group_email)
    if not to_addr:
        return False, "no recipient (no requester_email and no group_email)"

    target = job.get("target_host", "(unknown)")
    job_id = job.get("id", "(unknown)")
    marker_cn = _cn_from_dn(marker_dn)
    error_text = (error or "").strip() or "(no error message provided)"

    subject = f"[CSR Dashboard] Request failed for {target}"
    body = (
        "A CSR request has been marked failed.\n"
        "\n"
        f"Target host:  {target}\n"
        f"Job ID:       {job_id}\n"
        f"Marked by:    {marker_cn}\n"
        f"Error:        {error_text}\n"
        f"Timestamp:    {_utc_now()}\n"
        "\n"
        "View the job in the dashboard:\n"
        f"  {_dashboard_url()}\n"
        "\n"
        "This is an automated message from the CSR Dashboard at\n"
        "nipat-pl-rcdn01.eucom.mil. Do not reply to this address.\n"
    )
    return _compose_and_send(
        subject=subject, body=body,
        to_addr=to_addr, cc_addrs=cc,
        event_tag="failed", job_id=job_id,
    )


def send_feedback_received(feedback, admin_emails, submitter_cn, submitter_email=None):
    """Notify admins when a user submits feedback through the dashboard.

    All admin emails go in a single To: header since admins on a team
    typically know each other. If your environment requires recipient
    privacy, replace msg["To"] with msg["From"] and rely on the envelope
    (recipients arg to _send_message) for delivery.
    """
    if not _enabled:
        return False, f"notifications disabled ({_disabled_reason})"
    if not admin_emails:
        return False, "no admin recipients with email"

    try:
        from_addr = _config.get("from", "address").strip()
    except configparser.Error as e:
        return False, f"config read error: {e}"

    category = feedback.get("category", "general")
    feedback_id = feedback.get("id", "?")
    message = feedback.get("message", "")

    from_line = submitter_cn
    if submitter_email:
        from_line = f"{submitter_cn} <{submitter_email}>"

    subject = f"[CSR Dashboard] New {category} feedback from {submitter_cn}"
    body = (
        "A user has submitted feedback in the CSR Dashboard.\n"
        "\n"
        f"From:        {from_line}\n"
        f"Category:    {category}\n"
        f"Submitted:   {_utc_now()}\n"
        f"Feedback ID: #{feedback_id}\n"
        "\n"
        "Message:\n"
        "---\n"
        f"{message}\n"
        "---\n"
        "\n"
        "Review and respond in the admin dashboard:\n"
        f"  {_dashboard_url()}#admin\n"
        "\n"
        "This is an automated message from the CSR Dashboard at\n"
        "nipat-pl-rcdn01.eucom.mil. Do not reply to this address.\n"
    )

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(admin_emails)
    msg["Subject"] = subject
    msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-CSR-Dashboard-Event"] = "feedback_received"
    msg["X-CSR-Dashboard-Feedback-Id"] = str(feedback_id)
    msg.set_content(body)

    try:
        _send_message(msg, admin_emails)
        return True, "sent"
    except (smtplib.SMTPException, socket.error, OSError) as e:
        return False, f"{type(e).__name__}: {str(e)[:160]}"


def send_csrs_created(targets, cert_type, creator_cn, creator_email, recipients):
    """Notify signer-group recipients that new CSR(s) are awaiting signing.

    `targets` is a list of target hostnames/CNs; one aggregated email is
    sent per call (a batch generate produces one message, not N).
    Returns (ok, reason). Never raises.
    """
    if not _enabled:
        return False, f"notifications disabled ({_disabled_reason})"
    if not recipients:
        return False, "no signer recipients"
    if not targets:
        return False, "no targets"

    try:
        from_addr = _config.get("from", "address").strip()
    except configparser.Error as e:
        return False, f"config read error: {e}"

    n = len(targets)
    creator_line = creator_cn or "(unknown)"
    if creator_email:
        creator_line = f"{creator_line} <{creator_email}>"

    target_lines = "\n".join(f"  - {t}" for t in targets)
    plural = "s" if n != 1 else ""

    subject = f"[CSR Dashboard] {n} new CSR{plural} awaiting signing"
    body = (
        f"{n} new certificate signing request{plural} ha{'ve' if n != 1 else 's'} "
        "been created and are awaiting signing.\n"
        "\n"
        f"Requested by: {creator_line}\n"
        f"Cert type(s): {cert_type or 'unspecified'}\n"
        f"Timestamp:    {_utc_now()}\n"
        "\n"
        f"Target host{plural}:\n"
        f"{target_lines}\n"
        "\n"
        "Review and download the CSRs for signing:\n"
        f"  {_dashboard_url()}\n"
        "\n"
        "This is an automated message from the CSR Dashboard at\n"
        "nipat-pl-rcdn01.eucom.mil. Do not reply to this address.\n"
    )

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-CSR-Dashboard-Event"] = "csrs_created"
    msg.set_content(body)

    try:
        _send_message(msg, list(recipients))
        return True, "sent"
    except (smtplib.SMTPException, socket.error, OSError) as e:
        return False, f"{type(e).__name__}: {str(e)[:160]}"


def get_settings():
    """Current email configuration as a dict, plus enabled state. Secrets
    (smtp password, mailgun api key) are never returned in clear — only a
    boolean '*_set' so the UI can show a 'leave blank to keep' placeholder."""
    cfg = configparser.ConfigParser()
    if CONFIG_PATH.exists():
        try:
            cfg.read(CONFIG_PATH)
        except configparser.Error:
            pass
    return {
        "provider": _provider_of(cfg),
        # SMG / SMTP shared
        "host": cfg.get("smtp", "host", fallback=""),
        "port": cfg.getint("smtp", "port", fallback=25),
        "timeout": cfg.getint("smtp", "timeout", fallback=10),
        "security": cfg.get("smtp", "security", fallback="none"),
        "username": cfg.get("smtp", "username", fallback=""),
        "password_set": bool(cfg.get("smtp", "password", fallback="").strip()),
        # Mailgun
        "mailgun_domain": cfg.get("mailgun", "domain", fallback=""),
        "mailgun_base_url": cfg.get("mailgun", "base_url",
                                    fallback="https://api.mailgun.net"),
        "mailgun_api_key_set": bool(cfg.get("mailgun", "api_key", fallback="").strip()),
        # Common
        "from_address": cfg.get("from", "address", fallback=""),
        "cc": cfg.get("recipients", "cc", fallback=""),
        "dashboard_url": cfg.get("content", "dashboard_url",
                                 fallback="https://nipat-pl-rcdn01.eucom.mil/csr/"),
        "enabled": _enabled,
        "disabled_reason": _disabled_reason,
        "config_path": str(CONFIG_PATH),
    }


def save_settings(d):
    """Write new settings to email.conf and hot-reload. Returns (ok, reason).
    Secrets left blank are preserved from the existing file (the UI sends
    blank when the admin doesn't re-type them). File must be writable by the
    service account (csrapi)."""
    existing = configparser.ConfigParser()
    if CONFIG_PATH.exists():
        try:
            existing.read(CONFIG_PATH)
        except configparser.Error:
            pass

    def keep_secret(section, key, incoming):
        v = (incoming or "").strip()
        return v if v else existing.get(section, key, fallback="")

    provider = (d.get("provider") or "smg").strip().lower()
    if provider not in VALID_PROVIDERS:
        provider = "smg"

    cfg = configparser.ConfigParser()
    cfg["method"] = {"provider": provider}
    cfg["smtp"] = {
        "host": (d.get("host") or "").strip(),
        "port": str(int(d.get("port") or (587 if provider == "smtp" else 25))),
        "timeout": str(int(d.get("timeout") or 10)),
        "security": (d.get("security") or "none").strip().lower(),
        "username": (d.get("username") or "").strip(),
        "password": keep_secret("smtp", "password", d.get("password")),
    }
    cfg["mailgun"] = {
        "api_key": keep_secret("mailgun", "api_key", d.get("mailgun_api_key")),
        "domain": (d.get("mailgun_domain") or "").strip(),
        "base_url": (d.get("mailgun_base_url") or "https://api.mailgun.net").strip(),
    }
    cfg["from"] = {"address": (d.get("from_address") or "").strip()}
    cfg["recipients"] = {"cc": (d.get("cc") or "").strip()}
    cfg["content"] = {"dashboard_url": (d.get("dashboard_url") or "").strip()}

    try:
        with open(CONFIG_PATH, "w") as f:
            f.write("# /etc/csr-dashboard/email.conf\n")
            f.write("# Managed via the dashboard admin UI. [method] provider selects\n")
            f.write("# the active delivery method (smg|smtp|mailgun). Manual edits are\n")
            f.write("# preserved only for known keys; comments are not.\n")
            cfg.write(f)
    except OSError as e:
        return False, f"could not write {CONFIG_PATH}: {e}"

    _load_config()
    if not _enabled:
        return True, f"saved, but notifications disabled: {_disabled_reason}"
    return True, f"saved and reloaded (provider: {provider})"


def send_expiry_warning(job, days_left, group_email=None):
    """Warn the requester (Cc group) that an issued cert is approaching
    expiry. Returns (ok, reason). Never raises."""
    if not _enabled:
        return False, f"notifications disabled ({_disabled_reason})"
    recipient = (job.get("requester_email") or "").strip()
    if isinstance(group_email, (list, tuple)):
        cc = [a.strip() for a in group_email if a and a.strip()]
    else:
        cc = [a for a in [(group_email or "").strip()] if a]
    # Dedupe, and never Cc the To address
    seen = {recipient.lower()} if recipient else set()
    cc = [a for a in cc if a.lower() not in seen and not seen.add(a.lower())]
    if not recipient and not cc:
        return False, "no recipient"
    if not recipient and cc:
        recipient, cc = cc[0], cc[1:]

    try:
        from_addr = _config.get("from", "address").strip()
    except configparser.Error as e:
        return False, f"config read error: {e}"

    exp_str = time.strftime("%Y-%m-%d", time.gmtime(job.get("expires_at") or 0))
    subject = (f"[CSR Dashboard] Certificate for {job['target_host']} "
               f"expires in {days_left} day{'s' if days_left != 1 else ''}")
    locations = job.get("locations") or []
    loc_block = ""
    if locations:
        loc_block = ("\nThis certificate was found at:\n" +
                     "".join(f"  - {l}\n" for l in locations[:25]))
        if len(locations) > 25:
            loc_block += f"  ... and {len(locations) - 25} more\n"
    body = (
        f"The certificate for {job['target_host']} expires on {exp_str} "
        f"({days_left} day{'s' if days_left != 1 else ''} from now).\n"
        f"{loc_block}"
        "\n"
        "To renew: open the job in the dashboard and use the Renew button.\n"
        "It generates a fresh key and CSR with the same names and usages,\n"
        "ready for signing.\n"
        "\n"
        f"  {_dashboard_url()}\n"
        "\n"
        f"Job ID: {job['id']}\n"
        "\n"
        "This is an automated message from the CSR Dashboard at\n"
        "nipat-pl-rcdn01.eucom.mil. Do not reply to this address.\n"
    )

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = recipient
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-CSR-Dashboard-Event"] = "expiry_warning"
    msg.set_content(body)

    try:
        _send_message(msg, [recipient] + cc)
        return True, "sent"
    except (smtplib.SMTPException, socket.error, OSError) as e:
        return False, f"{type(e).__name__}: {str(e)[:160]}"
