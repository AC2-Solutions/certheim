"""acme_dns.py - cloud DNS-01 challenge solvers for the ACME provider.

Phase 2 of ACME support: DNS-01 against managed DNS providers, so the ACME
client (acme_client.py) works for public / SaaS deployments, not just internal
RFC2136 (Dns01Rfc2136Solver, which stays in acme_client.py).

Each solver sets `_acme-challenge.<domain>` TXT = base64url(sha256(keyAuth)) and
removes it on cleanup, exactly like the RFC2136 solver - they're interchangeable
behind the same `challenge_type = "dns-01"` / setup() / cleanup() interface.

Dependency-free (REST over urllib + stdlib crypto), matching the rest of the
app: Cloudflare uses a Bearer token, Route53 uses hand-rolled AWS SigV4, Azure
uses the OAuth2 client-credentials flow. Secrets (API tokens, keys) are passed
in by sign.py from the service environment; non-secret config (zone ids, region)
comes from app_settings.
"""
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from acme_client import AcmeError, b64u


def _txt_value(key_authorization):
    """The DNS-01 TXT record value for a key authorization (RFC 8555 §8.4)."""
    return b64u(hashlib.sha256(key_authorization.encode()).digest())


def _suffixes(domain):
    """Progressively shorter parent suffixes of a domain, for zone discovery:
    a.b.example.com -> [a.b.example.com, b.example.com, example.com]."""
    labels = domain.strip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _http(method, url, headers=None, body=None, timeout=20):
    """Minimal HTTP for the provider REST APIs. Returns (status, headers, body
    bytes). Tests monkeypatch this. Raises AcmeError on transport failure."""
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read() if hasattr(e, "read") else b"")
    except urllib.error.URLError as e:
        raise AcmeError(f"DNS provider unreachable at {url}: {e.reason}")


# --------------------------------------------------------------------------
# Cloudflare
# --------------------------------------------------------------------------
class Dns01CloudflareSolver:
    challenge_type = "dns-01"
    API = "https://api.cloudflare.com/client/v4"

    def __init__(self, api_token, zone=None, *, propagation_wait=15):
        if not api_token:
            raise AcmeError("Cloudflare DNS-01 requires CSR_ACME_DNS_API_TOKEN")
        self.api_token = api_token
        self.zone = (zone or "").strip()
        self.propagation_wait = int(propagation_wait)
        self._created = []   # (zone_id, record_id)

    def _h(self):
        return {"Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json"}

    def _zone_id(self, domain):
        for zname in ([self.zone] if self.zone else _suffixes(domain)):
            st, _, body = _http("GET", f"{self.API}/zones?name={zname}", headers=self._h())
            res = (json.loads(body or b"{}").get("result") or []) if st < 300 else []
            if res:
                return res[0]["id"]
        raise AcmeError(f"Cloudflare zone for '{domain}' not found "
                        "(check the API token's zone access / acme_dns_zone)")

    def setup(self, domain, token, key_authorization):
        zid = self._zone_id(domain)
        body = json.dumps({"type": "TXT", "name": f"_acme-challenge.{domain}",
                           "content": _txt_value(key_authorization), "ttl": 60}).encode()
        st, _, b = _http("POST", f"{self.API}/zones/{zid}/dns_records",
                         headers=self._h(), body=body)
        d = json.loads(b or b"{}")
        if not d.get("success"):
            raise AcmeError(f"Cloudflare TXT create failed: {d.get('errors')}")
        self._created.append((zid, d["result"]["id"]))
        time.sleep(self.propagation_wait)

    def cleanup(self):
        for zid, rid in self._created:
            try:
                _http("DELETE", f"{self.API}/zones/{zid}/dns_records/{rid}", headers=self._h())
            except AcmeError:
                pass
        self._created = []


# --------------------------------------------------------------------------
# AWS Route53 (hand-rolled SigV4)
# --------------------------------------------------------------------------
def _sha256_hex(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def _aws_canonical_request(method, path, query, signed, payload_hash):
    """Build the SigV4 canonical request. `signed` is an ordered dict of the
    headers to sign (lowercased names)."""
    canon_headers = "".join(f"{k}:{v}\n" for k, v in signed.items())
    signed_names = ";".join(signed.keys())
    return ("\n".join([method, path, query, canon_headers, signed_names,
                       payload_hash]), signed_names)


def _aws_signing_key(secret_key, datestamp, region, service):
    def _s(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()
    k = _s(("AWS4" + secret_key).encode(), datestamp)
    k = _s(k, region)
    k = _s(k, service)
    return _s(k, "aws4_request")


def aws_sigv4_headers(method, host, path, query, payload, access_key, secret_key,
                      *, region, service, amzdate, datestamp, session_token=None,
                      extra_signed=None):
    """Return the signed request headers for an AWS API call. `amzdate`
    (YYYYMMDDThhmmssZ) + `datestamp` (YYYYMMDD) are passed in so this is
    deterministic + unit-testable against published SigV4 vectors."""
    payload_hash = _sha256_hex(payload)
    signed = {"host": host}
    if extra_signed:
        signed.update(extra_signed)
    signed["x-amz-date"] = amzdate
    if session_token:
        signed["x-amz-security-token"] = session_token
    signed = dict(sorted(signed.items()))
    canonical, signed_names = _aws_canonical_request(method, path, query, signed, payload_hash)
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, _sha256_hex(canonical)])
    sig = hmac.new(_aws_signing_key(secret_key, datestamp, region, service),
                   sts.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_names}, Signature={sig}")
    headers = {"Authorization": auth, "x-amz-date": amzdate}
    if extra_signed:
        headers.update(extra_signed)
    if session_token:
        headers["x-amz-security-token"] = session_token
    return headers


class Dns01Route53Solver:
    challenge_type = "dns-01"
    HOST = "route53.amazonaws.com"
    REGION = "us-east-1"           # Route53 is global; SigV4 uses us-east-1
    SERVICE = "route53"

    def __init__(self, access_key, secret_key, hosted_zone_id, *,
                 session_token=None, propagation_wait=25):
        if not (access_key and secret_key and hosted_zone_id):
            raise AcmeError("Route53 DNS-01 requires CSR_ACME_DNS_ACCESS_KEY, "
                            "CSR_ACME_DNS_SECRET_KEY, and acme_dns_zone (hosted zone id)")
        self.access_key = access_key
        self.secret_key = secret_key
        self.zone_id = hosted_zone_id.strip().replace("/hostedzone/", "")
        self.session_token = session_token
        self.propagation_wait = int(propagation_wait)
        self._pending = []   # (name, value) UPSERTed, to DELETE on cleanup

    def _change(self, action, name, value):
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<ChangeResourceRecordSetsRequest '
            'xmlns="https://route53.amazonaws.com/doc/2013-04-01/">'
            f'<ChangeBatch><Changes><Change><Action>{action}</Action>'
            f'<ResourceRecordSet><Name>{name}</Name><Type>TXT</Type><TTL>60</TTL>'
            f'<ResourceRecords><ResourceRecord><Value>"{value}"</Value>'
            '</ResourceRecord></ResourceRecords></ResourceRecordSet>'
            '</Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>'
        ).encode()
        path = f"/2013-04-01/hostedzone/{self.zone_id}/rrset"
        t = time.gmtime()
        headers = aws_sigv4_headers(
            "POST", self.HOST, path, "", body, self.access_key, self.secret_key,
            region=self.REGION, service=self.SERVICE,
            amzdate=time.strftime("%Y%m%dT%H%M%SZ", t),
            datestamp=time.strftime("%Y%m%d", t),
            session_token=self.session_token,
            extra_signed={"x-amz-content-sha256": _sha256_hex(body)})
        st, _, resp = _http("POST", f"https://{self.HOST}{path}", headers=headers, body=body)
        if st >= 300:
            raise AcmeError(f"Route53 {action} HTTP {st}: "
                            f"{resp.decode('utf-8', 'replace')[:200]}")

    def setup(self, domain, token, key_authorization):
        name = f"_acme-challenge.{domain}."
        value = _txt_value(key_authorization)
        self._change("UPSERT", name, value)
        self._pending.append((name, value))
        time.sleep(self.propagation_wait)

    def cleanup(self):
        for name, value in self._pending:
            try:
                self._change("DELETE", name, value)
            except AcmeError:
                pass
        self._pending = []


# --------------------------------------------------------------------------
# Azure DNS
# --------------------------------------------------------------------------
class Dns01AzureSolver:
    challenge_type = "dns-01"
    MGMT = "https://management.azure.com"

    def __init__(self, tenant, client_id, client_secret, subscription,
                 resource_group, zone, *, propagation_wait=20):
        if not all([tenant, client_id, client_secret, subscription, resource_group, zone]):
            raise AcmeError("Azure DNS-01 requires tenant/client/secret (env) + "
                            "acme_dns_zone as 'subscription/resourceGroup/zone'")
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription = subscription
        self.resource_group = resource_group
        self.zone = zone.strip(".")
        self.propagation_wait = int(propagation_wait)
        self._created = []   # relative record names

    def _token(self):
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials", "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": f"{self.MGMT}/.default"}).encode()
        st, _, b = _http("POST",
                         f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token",
                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                         body=body)
        tok = json.loads(b or b"{}").get("access_token")
        if not tok:
            raise AcmeError(f"Azure token request failed (HTTP {st})")
        return tok

    def _record_url(self, rel):
        return (f"{self.MGMT}/subscriptions/{self.subscription}/resourceGroups/"
                f"{self.resource_group}/providers/Microsoft.Network/dnsZones/"
                f"{self.zone}/TXT/{rel}?api-version=2018-05-01")

    def _rel(self, domain):
        rel = f"_acme-challenge.{domain}"
        if rel.endswith("." + self.zone):
            rel = rel[: -(len(self.zone) + 1)]
        return rel

    def setup(self, domain, token, key_authorization):
        rel = self._rel(domain)
        body = json.dumps({"properties": {"TTL": 60, "TXTRecords": [
            {"value": [_txt_value(key_authorization)]}]}}).encode()
        st, _, b = _http("PUT", self._record_url(rel),
                         headers={"Authorization": f"Bearer {self._token()}",
                                  "Content-Type": "application/json"}, body=body)
        if st >= 300:
            raise AcmeError(f"Azure TXT PUT HTTP {st}: {b.decode('utf-8','replace')[:200]}")
        self._created.append(rel)
        time.sleep(self.propagation_wait)

    def cleanup(self):
        for rel in self._created:
            try:
                _http("DELETE", self._record_url(rel),
                      headers={"Authorization": f"Bearer {self._token()}"})
            except AcmeError:
                pass
        self._created = []
