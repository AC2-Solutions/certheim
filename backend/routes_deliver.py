"""routes_deliver blueprint - the pull-delivery fetch endpoint.

Public by design: the bearer of a valid pull token IS authorized (the token is a
random, single-use, short-lived capability minted by the `pull` delivery
provider in deliver.py). No session/CAC is required, so a destination host can
fetch its own cert with nothing but the token. Unknown / expired / exhausted
tokens all return an identical 404 so the endpoint is not an existence oracle.
"""
from flask import Blueprint, Response, jsonify, request

import deliver

bp = Blueprint("deliver", __name__)


def _client_ip():
    fwd = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return fwd or (request.remote_addr or "")


@bp.get("/deliver/pull/<token>")
def pull(token):
    """Fetch + consume a pull bundle. ?format=pem returns cert(+key) as PEM text;
    ?format=cert returns just the leaf cert; default is JSON."""
    bundle = deliver.consume_pull(token, ip=_client_ip())
    if not bundle:
        # Don't distinguish unknown / expired / already-used.
        return jsonify(error="not found"), 404

    from app import log_event
    log_event("delivery", "pull", host=bundle.get("target_host"),
              fmt=(request.args.get("format") or "json"))

    fmt = (request.args.get("format") or "json").lower()
    cert = bundle["certificate"]
    key = bundle.get("private_key")
    if fmt == "cert":
        return Response(cert, mimetype="application/x-pem-file")
    if fmt == "pem":
        body = cert if cert.endswith("\n") else cert + "\n"
        if key:
            body += key if key.endswith("\n") else key + "\n"
        return Response(body, mimetype="application/x-pem-file")
    out = {"certificate": cert, "target_host": bundle.get("target_host")}
    if key:
        out["private_key"] = key
    return jsonify(out)
