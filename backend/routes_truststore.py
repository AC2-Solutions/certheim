"""routes_truststore blueprint - the in-app CA trust store.

Admin endpoints (session/CAC + admin + CSRF) to upload roots/intermediates,
build & download the CA bundle, install it on this host, manage fleet targets
and push the bundle to them over SSH, and mint a pull token + install script.

Plus ONE public endpoint - GET /api/truststore/bundle/<token> - so a fleet host
can fetch the bundle with nothing but a token (the token is the capability). The
bundle is public CA material (no private keys); unknown/expired tokens 404 with
no detail so the endpoint is not an existence oracle.
"""
from flask import Blueprint, Response, g, jsonify, request

import truststore

bp = Blueprint("truststore", __name__)


def _client_ip():
    fwd = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return fwd or (request.remote_addr or "")


# Routes are defined inside _register() so the app's auth decorators
# (require_admin/require_csrf) and log_event can be imported lazily, avoiding an
# import cycle at module load (app.py imports this blueprint).
def _register():
    from app import require_admin, require_csrf, log_event

    @bp.get("/api/admin/truststore")
    @require_admin
    def ts_list():
        return jsonify(certs=truststore.list_certs(),
                       bundle=truststore.bundle_meta(),
                       targets=truststore.list_targets())

    @bp.post("/api/admin/truststore/upload")
    @require_admin
    @require_csrf
    def ts_upload():
        body = request.get_json(silent=True) or {}
        pem = (body.get("pem") or "").strip()
        if not pem:
            return jsonify(error="paste one or more PEM CA certificates"), 400
        try:
            res = truststore.add_certs(
                pem, name=(body.get("name") or "").strip() or None,
                notes=(body.get("notes") or "").strip() or None,
                actor=(g.identity or {}).get("dn"))
        except truststore.TrustError as e:
            return jsonify(error=str(e)), 400
        log_event("truststore_upload", "ok",
                  added=len(res["added"]), dupes=len(res["duplicates"]))
        return jsonify(**res)

    @bp.post("/api/admin/truststore/<int:cert_id>/enabled")
    @require_admin
    @require_csrf
    def ts_set_enabled(cert_id):
        body = request.get_json(silent=True) or {}
        ok = truststore.set_enabled(cert_id, bool(body.get("enabled")))
        if not ok:
            return jsonify(error="not found"), 404
        log_event("truststore_enabled", "ok", id=cert_id, enabled=bool(body.get("enabled")))
        return jsonify(ok=True)

    @bp.delete("/api/admin/truststore/<int:cert_id>")
    @require_admin
    @require_csrf
    def ts_delete(cert_id):
        if not truststore.remove(cert_id):
            return jsonify(error="not found"), 404
        log_event("truststore_delete", "ok", id=cert_id)
        return jsonify(ok=True)

    @bp.get("/api/admin/truststore/bundle")
    @require_admin
    def ts_download_bundle():
        bundle = truststore.build_bundle()
        if not bundle.strip():
            return jsonify(error="trust store is empty"), 404
        return Response(bundle, mimetype="application/x-pem-file",
                        headers={"Content-Disposition":
                                 "attachment; filename=certinel-trust-bundle.pem"})

    @bp.post("/api/admin/truststore/install-local")
    @require_admin
    @require_csrf
    def ts_install_local():
        try:
            out = truststore.install_local()
        except truststore.TrustError as e:
            log_event("truststore_install_local", "error", detail=str(e)[:160])
            return jsonify(error=str(e)), 400
        log_event("truststore_install_local", "ok")
        return jsonify(ok=True, detail=out)

    # --- fleet targets ---
    @bp.post("/api/admin/truststore/targets")
    @require_admin
    @require_csrf
    def ts_add_target():
        body = request.get_json(silent=True) or {}
        try:
            truststore.add_target((body.get("host") or "").strip(),
                                  label=(body.get("label") or "").strip() or None,
                                  actor=(g.identity or {}).get("dn"))
        except truststore.TrustError as e:
            return jsonify(error=str(e)), 400
        log_event("truststore_target_add", "ok", host=(body.get("host") or "")[:120])
        return jsonify(targets=truststore.list_targets())

    @bp.delete("/api/admin/truststore/targets/<int:target_id>")
    @require_admin
    @require_csrf
    def ts_del_target(target_id):
        if not truststore.remove_target(target_id):
            return jsonify(error="not found"), 404
        log_event("truststore_target_del", "ok", id=target_id)
        return jsonify(targets=truststore.list_targets())

    @bp.post("/api/admin/truststore/push")
    @require_admin
    @require_csrf
    def ts_push():
        body = request.get_json(silent=True) or {}
        host = (body.get("host") or "").strip() or None
        results = truststore.push_targets(host_filter=host)
        ok = sum(1 for r in results if r["ok"])
        log_event("truststore_push", "ok", hosts=len(results), succeeded=ok)
        return jsonify(results=results, targets=truststore.list_targets())

    # --- pull token + install script ---
    @bp.post("/api/admin/truststore/pull-token")
    @require_admin
    @require_csrf
    def ts_pull_token():
        tok = truststore.mint_pull_token()
        log_event("truststore_pull_token", "ok")
        return jsonify(**tok, script=truststore.install_script(tok["token"]))

    # PUBLIC: a host fetches the bundle with just the token.
    @bp.get("/api/truststore/bundle/<token>")
    def ts_pull_bundle(token):
        bundle = truststore.consume_pull(token, ip=_client_ip())
        if bundle is None:
            return jsonify(error="not found"), 404
        log_event("truststore_pull", "ok")
        return Response(bundle, mimetype="application/x-pem-file")


_register()
