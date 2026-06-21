"""routes_acme.py - the dashboard's ACME server (RFC 8555) HTTP endpoints.

Phase 4: certbot / cert-manager / acme.sh point their --server at the dashboard
and enroll directly; the dashboard validates domain control (HTTP-01) and signs
the finalize CSR through the configured signing backend (OpenBao, Windows CA,
ACME-client, ...). The crypto + protocol core is acme_server.py.

These routes are PUBLIC (ACME clients have no CAC) and authenticated per-request
by JWS over the client's account key. The whole server is OFF unless the admin
enables it AND the deployment is entitled (capability ca.server.acme); when off
the directory 404s so it isn't advertised.

MVP scope: directory, new-nonce, new-account, new-order, authz, challenge
(HTTP-01), finalize (sign via backend), certificate. Revoke, DNS-01 validation,
and account key rollover are follow-ons.
"""
import json
import os
import time

from flask import Blueprint, request, jsonify, make_response, abort

import acme_server
import capabilities
import sign
from acme_server import AcmeServerError
from app import (db, get_setting, log_event, resolve_signing_policy,
                 _dashboard_base, _cert_serial_colons)

bp = Blueprint("acme", __name__, url_prefix="/acme")

CAP_ACME_SERVER = "ca.server.acme"
NONCE_TTL = 8 * 3600          # nonces older than this are swept


# --------------------------------------------------------------------------
# enablement + URL helpers
# --------------------------------------------------------------------------
def _enabled():
    return ((get_setting("acme_server_enabled") or "0") in ("1", "true", "yes", "on")
            and capabilities.available(CAP_ACME_SERVER))


def _base():
    """External base URL for ACME resources (clients must be able to reach it).
    Admin override `acme_server_base_url`, else the dashboard URL + /acme."""
    b = (get_setting("acme_server_base_url") or "").strip()
    if not b:
        b = _dashboard_base().rstrip("/") + "/acme"
    return b.rstrip("/")


def _u(*parts):
    return "/".join([_base()] + [str(p).strip("/") for p in parts])


# --------------------------------------------------------------------------
# nonces (single-use, replay protection)
# --------------------------------------------------------------------------
def _new_nonce():
    n = acme_server.b64u(os.urandom(18))
    now = time.time()
    with db() as c:
        c.execute("INSERT INTO acme_nonces (nonce, created_at) VALUES (?, ?)", (n, now))
        c.execute("DELETE FROM acme_nonces WHERE created_at < ?", (now - NONCE_TTL,))
    return n


def _consume_nonce(n):
    if not n:
        return False
    with db() as c:
        cur = c.execute("DELETE FROM acme_nonces WHERE nonce = ?", (n,))
        return cur.rowcount > 0


def _resp(body, status=200, headers=None):
    """ACME JSON response with a fresh Replay-Nonce on every reply."""
    r = make_response(jsonify(body) if not isinstance(body, str) else body, status)
    r.headers["Replay-Nonce"] = _new_nonce()
    r.headers["Cache-Control"] = "no-store"
    if headers:
        for k, v in headers.items():
            r.headers[k] = v
    return r


def _problem(e):
    r = make_response(jsonify({"type": f"urn:ietf:params:acme:error:{e.problem_type}",
                               "detail": str(e)}), e.status)
    r.headers["Content-Type"] = "application/problem+json"
    r.headers["Replay-Nonce"] = _new_nonce()
    return r


# --------------------------------------------------------------------------
# JWS parsing / account lookup
# --------------------------------------------------------------------------
def _account(acct_id):
    with db() as c:
        return c.execute("SELECT * FROM acme_accounts WHERE id = ?", (acct_id,)).fetchone()


def _parse_jws(path_suffix):
    """Validate an inbound JWS POST: consume the nonce, bind the url, verify the
    signature against the embedded jwk (new-account) or the kid's account key.
    Returns (payload_obj_or_None, jwk, account_row_or_None)."""
    body = request.get_json(force=True, silent=True) or {}
    for k in ("protected", "payload", "signature"):
        if k not in body:
            raise AcmeServerError(f"JWS missing '{k}'")
    try:
        protected = json.loads(acme_server.b64u_decode(body["protected"]))
    except Exception:
        raise AcmeServerError("unparseable JWS protected header")
    if not _consume_nonce(protected.get("nonce")):
        raise AcmeServerError("bad or already-used anti-replay nonce", "badNonce")
    url = (protected.get("url") or "").rstrip("/")
    if not url.endswith(path_suffix):
        raise AcmeServerError("JWS 'url' does not match the request target", "unauthorized", 401)

    account = None
    if "jwk" in protected:
        jwk = protected["jwk"]
    elif "kid" in protected:
        account = _account(protected["kid"].rstrip("/").split("/")[-1])
        if not account:
            raise AcmeServerError("account does not exist", "accountDoesNotExist")
        jwk = json.loads(account["jwk_json"])
    else:
        raise AcmeServerError("JWS must carry 'jwk' or 'kid'")

    acme_server.verify_jws(body["protected"], body["payload"], body["signature"],
                           jwk, protected.get("alg"))
    payload = (json.loads(acme_server.b64u_decode(body["payload"]))
               if body["payload"] else None)
    return payload, jwk, account


# --------------------------------------------------------------------------
# directory + nonce
# --------------------------------------------------------------------------
@bp.get("/directory")
def directory():
    if not _enabled():
        abort(404)
    return _resp({
        "newNonce": _u("new-nonce"), "newAccount": _u("new-account"),
        "newOrder": _u("new-order"), "revokeCert": _u("revoke-cert"),
        "keyChange": _u("key-change"),
        "meta": {"externalAccountRequired": False,
                 "website": _dashboard_base()},
    })


@bp.route("/new-nonce", methods=["GET", "HEAD"])
def new_nonce():
    if not _enabled():
        abort(404)
    r = make_response("", 200)
    r.headers["Replay-Nonce"] = _new_nonce()
    r.headers["Cache-Control"] = "no-store"
    return r


# --------------------------------------------------------------------------
# accounts
# --------------------------------------------------------------------------
@bp.post("/new-account")
def new_account():
    if not _enabled():
        abort(404)
    try:
        payload, jwk, _ = _parse_jws("/acme/new-account")
        thumb = acme_server.jwk_thumbprint(jwk)
        with db() as c:
            acct = c.execute("SELECT * FROM acme_accounts WHERE thumbprint = ?",
                             (thumb,)).fetchone()
        if acct:
            aid, code = acct["id"], 200
        else:
            aid, code = acme_server.new_id(), 201
            contact = json.dumps((payload or {}).get("contact", []))
            with db() as c:
                c.execute("INSERT INTO acme_accounts (id, thumbprint, jwk_json, "
                          "contact, status, created_at) VALUES (?,?,?,?, 'valid', ?)",
                          (aid, thumb, json.dumps(jwk), contact, time.time()))
            log_event("acme_server", "new_account", account=aid)
        return _resp({"status": "valid"}, code, {"Location": _u("account", aid)})
    except AcmeServerError as e:
        return _problem(e)


# --------------------------------------------------------------------------
# orders
# --------------------------------------------------------------------------
def _order_view(order):
    """Build the ACME order object; status is computed from its authzs."""
    with db() as c:
        authzs = c.execute("SELECT * FROM acme_authzs WHERE order_id = ?",
                           (order["id"],)).fetchall()
    status = order["status"]
    if status in ("pending", "ready"):
        status = "ready" if all(a["status"] == "valid" for a in authzs) else "pending"
    view = {
        "status": status,
        "expires": _iso(order["expires_at"]),
        "identifiers": [{"type": "dns", "value": d}
                        for d in json.loads(order["identifiers_json"])],
        "authorizations": [_u("authz", a["id"]) for a in authzs],
        "finalize": _u("order", order["id"], "finalize"),
    }
    if order["cert_id"]:
        view["certificate"] = _u("cert", order["cert_id"])
    if order["error"]:
        view["error"] = {"type": "urn:ietf:params:acme:error:serverInternal",
                         "detail": order["error"]}
    return view


@bp.post("/new-order")
def new_order():
    if not _enabled():
        abort(404)
    try:
        payload, _jwk, account = _parse_jws("/acme/new-order")
        if not account:
            raise AcmeServerError("new-order requires an account (kid)", "unauthorized", 401)
        dns = [i["value"].lower() for i in (payload or {}).get("identifiers", [])
               if i.get("type") == "dns" and i.get("value")]
        if not dns:
            raise AcmeServerError("no DNS identifiers in order")
        oid, now = acme_server.new_id(), time.time()
        with db() as c:
            c.execute("INSERT INTO acme_orders (id, account_id, status, "
                      "identifiers_json, created_at, expires_at) VALUES "
                      "(?,?, 'pending', ?, ?, ?)",
                      (oid, account["id"], json.dumps(dns), now, now + 7 * 86400))
            for d in dns:
                azid = acme_server.new_id()
                c.execute("INSERT INTO acme_authzs (id, order_id, identifier, status) "
                          "VALUES (?,?,?, 'pending')", (azid, oid, d))
                # Offer both http-01 and dns-01; the client satisfies one.
                for ctype in ("http-01", "dns-01"):
                    c.execute("INSERT INTO acme_challenges (id, authz_id, token, "
                              "type, status) VALUES (?,?,?,?, 'pending')",
                              (acme_server.new_id(), azid,
                               acme_server.b64u(os.urandom(24)), ctype))
        with db() as c:
            order = c.execute("SELECT * FROM acme_orders WHERE id = ?", (oid,)).fetchone()
        log_event("acme_server", "new_order", order=oid, identifiers=",".join(dns))
        return _resp(_order_view(order), 201, {"Location": _u("order", oid)})
    except AcmeServerError as e:
        return _problem(e)


@bp.post("/order/<oid>")
def get_order(oid):
    if not _enabled():
        abort(404)
    try:
        _parse_jws(f"/acme/order/{oid}")
        with db() as c:
            order = c.execute("SELECT * FROM acme_orders WHERE id = ?", (oid,)).fetchone()
        if not order:
            raise AcmeServerError("order not found", "malformed", 404)
        return _resp(_order_view(order))
    except AcmeServerError as e:
        return _problem(e)


# --------------------------------------------------------------------------
# authorizations + challenges
# --------------------------------------------------------------------------
def _authz_view(authz):
    with db() as c:
        chals = c.execute("SELECT * FROM acme_challenges WHERE authz_id = ?",
                          (authz["id"],)).fetchall()
    return {
        "status": authz["status"],
        "identifier": {"type": "dns", "value": authz["identifier"]},
        "challenges": [{"type": ch["type"], "url": _u("challenge", ch["id"]),
                        "token": ch["token"], "status": ch["status"]}
                       for ch in chals],
    }


@bp.post("/authz/<azid>")
def get_authz(azid):
    if not _enabled():
        abort(404)
    try:
        _parse_jws(f"/acme/authz/{azid}")
        with db() as c:
            authz = c.execute("SELECT * FROM acme_authzs WHERE id = ?", (azid,)).fetchone()
        if not authz:
            raise AcmeServerError("authorization not found", "malformed", 404)
        return _resp(_authz_view(authz))
    except AcmeServerError as e:
        return _problem(e)


@bp.post("/challenge/<chid>")
def respond_challenge(chid):
    if not _enabled():
        abort(404)
    try:
        _payload, _jwk, account = _parse_jws(f"/acme/challenge/{chid}")
        with db() as c:
            ch = c.execute("SELECT * FROM acme_challenges WHERE id = ?", (chid,)).fetchone()
            if not ch:
                raise AcmeServerError("challenge not found", "malformed", 404)
            authz = c.execute("SELECT * FROM acme_authzs WHERE id = ?",
                             (ch["authz_id"],)).fetchone()
            acct = account or c.execute(
                "SELECT a.* FROM acme_accounts a JOIN acme_orders o ON o.account_id=a.id "
                "WHERE o.id = ?", (authz["order_id"],)).fetchone()
        jwk = json.loads(acct["jwk_json"])
        key_auth = acme_server.key_authorization(ch["token"], jwk)
        if ch["type"] == "dns-01":
            ok, detail = acme_server.validate_dns01(authz["identifier"], key_auth)
        else:
            ok, detail = acme_server.validate_http01(authz["identifier"], ch["token"], key_auth)
        with db() as c:
            if ok:
                # one valid challenge authorizes the identifier
                c.execute("UPDATE acme_challenges SET status='valid' WHERE id=?", (chid,))
                c.execute("UPDATE acme_authzs SET status='valid' WHERE id=?", (authz["id"],))
            else:
                # only this challenge fails; the client may still try another
                c.execute("UPDATE acme_challenges SET status='invalid', error=? WHERE id=?",
                          (detail, chid))
        log_event("acme_server", "valid" if ok else "invalid", challenge=chid,
                  type=ch["type"], identifier=authz["identifier"])
        with db() as c:
            ch = c.execute("SELECT * FROM acme_challenges WHERE id = ?", (chid,)).fetchone()
        view = {"type": ch["type"], "url": _u("challenge", chid),
                "token": ch["token"], "status": ch["status"]}
        if ch["error"]:
            view["error"] = {"type": "urn:ietf:params:acme:error:unauthorized",
                             "detail": ch["error"]}
        return _resp(view)
    except AcmeServerError as e:
        return _problem(e)


# --------------------------------------------------------------------------
# finalize (sign the CSR via the configured backend) + certificate
# --------------------------------------------------------------------------
@bp.post("/order/<oid>/finalize")
def finalize(oid):
    if not _enabled():
        abort(404)
    try:
        payload, _jwk, account = _parse_jws(f"/acme/order/{oid}/finalize")
        with db() as c:
            order = c.execute("SELECT * FROM acme_orders WHERE id = ?", (oid,)).fetchone()
            if not order:
                raise AcmeServerError("order not found", "malformed", 404)
            authzs = c.execute("SELECT * FROM acme_authzs WHERE order_id = ?", (oid,)).fetchall()
        if not all(a["status"] == "valid" for a in authzs):
            raise AcmeServerError("order is not ready (authorizations not all valid)",
                                  "orderNotReady", 403)

        csr_pem = acme_server.csr_der_b64u_to_pem((payload or {}).get("csr", ""))
        want = set(json.loads(order["identifiers_json"]))
        got = acme_server.csr_dns_names(csr_pem)
        if got != want:
            raise AcmeServerError(f"CSR names {sorted(got)} do not match order "
                                  f"{sorted(want)}", "badCSR")

        # Sign through the configured default backend (the same CA the in-UI
        # signing uses). manual -> the server can't issue.
        policy = resolve_signing_policy(None)
        if (policy.get("signer_backend") or "manual") == "manual":
            raise AcmeServerError("no automated signing backend configured on the "
                                  "dashboard", "serverInternal", 500)
        try:
            result = sign.sign_csr(csr_pem, policy, actor="acme-server")
        except sign.SignError as e:
            with db() as c:
                c.execute("UPDATE acme_orders SET status='invalid', error=? WHERE id=?",
                          (str(e)[:300], oid))
            log_event("acme_server", "finalize_sign_error", order=oid, error=str(e)[:200])
            raise AcmeServerError(f"signing failed: {e}", "serverInternal", 500)

        cid = acme_server.new_id()
        leaf = result.cert_pem if result.cert_pem.endswith("\n") else result.cert_pem + "\n"
        pem = leaf + (result.chain_pem or "")
        serial = _cert_serial_colons(leaf)      # for revoke + tracking
        with db() as c:
            c.execute("INSERT INTO acme_certs (id, account_id, pem, serial) VALUES (?,?,?,?)",
                      (cid, order["account_id"], pem, serial))
            c.execute("UPDATE acme_orders SET status='valid', cert_id=? WHERE id=?", (cid, oid))
            order = c.execute("SELECT * FROM acme_orders WHERE id = ?", (oid,)).fetchone()
        log_event("acme_server", "issued", order=oid,
                  backend=policy.get("signer_backend"))
        return _resp(_order_view(order), 200, {"Location": _u("order", oid)})
    except AcmeServerError as e:
        return _problem(e)


@bp.post("/cert/<cid>")
def get_cert(cid):
    if not _enabled():
        abort(404)
    try:
        _parse_jws(f"/acme/cert/{cid}")
        with db() as c:
            row = c.execute("SELECT pem FROM acme_certs WHERE id = ?", (cid,)).fetchone()
        if not row:
            raise AcmeServerError("certificate not found", "malformed", 404)
        r = _resp(row["pem"])
        r.headers["Content-Type"] = "application/pem-certificate-chain"
        return r
    except AcmeServerError as e:
        return _problem(e)


# --------------------------------------------------------------------------
# revoke-cert (RFC 8555 §7.6) - revoke at the backing CA
# --------------------------------------------------------------------------
@bp.post("/revoke-cert")
def revoke_cert():
    if not _enabled():
        abort(404)
    try:
        payload, _jwk, account = _parse_jws("/acme/revoke-cert")
        if not account:
            raise AcmeServerError("revocation must be signed by the account key",
                                  "unauthorized", 401)
        cert_b64 = (payload or {}).get("certificate")
        if not cert_b64:
            raise AcmeServerError("no 'certificate' in revoke request")
        leaf_pem = acme_server.cert_der_to_pem(acme_server.b64u_decode(cert_b64))
        serial = _cert_serial_colons(leaf_pem)
        with db() as c:
            cert = c.execute("SELECT * FROM acme_certs WHERE serial = ?", (serial,)).fetchone()
        if not cert:
            raise AcmeServerError("certificate was not issued by this server", "malformed", 404)
        # Authorization: the account that ordered the cert (cert-key signing is a
        # follow-on).
        if account["id"] != cert["account_id"]:
            raise AcmeServerError("account is not authorized to revoke this certificate",
                                  "unauthorized", 403)
        if cert["revoked"]:
            return _resp("", 200)         # idempotent
        backend = (resolve_signing_policy(None).get("signer_backend") or "manual")
        try:
            sign.revoke_cert(serial, backend)
        except sign.SignError as e:
            raise AcmeServerError(f"backend revocation failed: {e}", "serverInternal", 500)
        with db() as c:
            c.execute("UPDATE acme_certs SET revoked=1 WHERE id=?", (cert["id"],))
        log_event("acme_server", "revoked", cert=cert["id"], serial=serial, backend=backend)
        return _resp("", 200)
    except AcmeServerError as e:
        return _problem(e)


# --------------------------------------------------------------------------
# key-change (RFC 8555 §7.3.5) - rotate the account key
# --------------------------------------------------------------------------
@bp.post("/key-change")
def key_change():
    if not _enabled():
        abort(404)
    try:
        outer_payload, _jwk, account = _parse_jws("/acme/key-change")
        if not account:
            raise AcmeServerError("key-change must be signed by the (old) account key",
                                  "unauthorized", 401)
        inner = outer_payload or {}
        for k in ("protected", "payload", "signature"):
            if k not in inner:
                raise AcmeServerError(f"inner JWS missing '{k}'")
        inner_prot = json.loads(acme_server.b64u_decode(inner["protected"]))
        new_jwk = inner_prot.get("jwk")
        if not new_jwk:
            raise AcmeServerError("inner JWS must carry the new key as 'jwk'")
        # The inner JWS proves possession of the NEW key.
        acme_server.verify_jws(inner["protected"], inner["payload"], inner["signature"],
                               new_jwk, inner_prot.get("alg"))
        inner_payload = json.loads(acme_server.b64u_decode(inner["payload"]))
        if (inner_payload.get("account") or "").rstrip("/").split("/")[-1] != account["id"]:
            raise AcmeServerError("inner 'account' does not match the signer", "malformed")
        if acme_server.jwk_thumbprint(inner_payload.get("oldKey") or {}) != account["thumbprint"]:
            raise AcmeServerError("inner 'oldKey' does not match the account key", "malformed")
        new_thumb = acme_server.jwk_thumbprint(new_jwk)
        with db() as c:
            clash = c.execute("SELECT id FROM acme_accounts WHERE thumbprint=? AND id<>?",
                              (new_thumb, account["id"])).fetchone()
            if clash:
                raise AcmeServerError("new key is already in use by another account",
                                      "malformed", 409)
            c.execute("UPDATE acme_accounts SET jwk_json=?, thumbprint=? WHERE id=?",
                      (json.dumps(new_jwk), new_thumb, account["id"]))
        log_event("acme_server", "key_change", account=account["id"])
        return _resp({"status": "valid"}, 200, {"Location": _u("account", account["id"])})
    except AcmeServerError as e:
        return _problem(e)


def _iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)) if epoch else None
