#!/usr/bin/env python3
"""A fake Lambda Invoke API: it checks the request the way AWS would, then answers with a scripted reply.

The interesting half is the signature. AWS answers a request whose SigV4 signature is even slightly off with 403 and
nothing else, so a test that only looks at the atom's exit code cannot tell a correct signer from a wrong one. This
server recomputes the signature from the bytes that arrived -- canonical request, string to sign, the four HMACs -- with
its own implementation, and refuses the request when the two disagree. It also records every request so the checks can
assert on the shape: the path, the log type header, the payload bytes.

usage: fake_lambda.py <port> <state-dir> <wire-log>

The reply is read from <state-dir>/respond.json on every request, so a check can change the scenario without restarting
the server:

    {"status": 200, "body": "{\\"ok\\": true}", "headers": {"x-amz-executed-version": "$LATEST"},
     "logResult": "REPORT RequestId: ...", "delay": 0, "contentLength": null, "expectRegion": "us-east-1"}

An unknown scenario is an empty 200. Every request is appended to <wire-log> as one JSON object per line.
"""
import base64
import calendar
import hashlib
import hmac
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
SESSION_TOKEN = "session/token+EXAMPLE"
REGION = "us-east-1"
SERVICE = "lambda"

STATE = sys.argv[2]
WIRE = sys.argv[3]


def sha256(data):
    return hashlib.sha256(data).digest()


def sign(key, message):
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def canonical_query(raw):
    if not raw:
        return ""
    pairs = []
    for piece in raw.split("&"):
        name, _, value = piece.partition("=")
        pairs.append((unquote(name), unquote(value)))
    pairs.sort()
    return "&".join("%s=%s" % (n, v) for n, v in pairs)


def verify(method, path, query, headers, body, expected_region=REGION):
    """Recompute the SigV4 signature of the request as it arrived. Returns (ok, reason, details)."""
    auth = headers.get("authorization", "")
    if not auth.startswith("AWS4-HMAC-SHA256 "):
        return False, "no AWS4-HMAC-SHA256 Authorization header", {}
    fields = {}
    for part in auth[len("AWS4-HMAC-SHA256 "):].split(","):
        name, _, value = part.strip().partition("=")
        fields[name] = value
    credential = fields.get("Credential", "")
    signed_headers = fields.get("SignedHeaders", "")
    signature = fields.get("Signature", "")
    pieces = credential.split("/")
    if len(pieces) != 5:
        return False, "credential scope is not akid/date/region/service/aws4_request", {}
    akid, date_stamp, region, service, terminator = pieces
    details = {"akid": akid, "region": region, "service": service, "signedHeaders": signed_headers}

    if akid != ACCESS_KEY:
        return False, "unknown access key id %r" % akid, details
    if region != expected_region or service != SERVICE or terminator != "aws4_request":
        return False, "credential scope is %s/%s/%s" % (region, service, terminator), details

    amz_date = headers.get("x-amz-date", "")
    if len(amz_date) != 16 or amz_date[8] != "T":
        return False, "x-amz-date is %r" % amz_date, details
    try:
        sent = time.strptime(amz_date, "%Y%m%dT%H%M%SZ")
    except ValueError:
        return False, "x-amz-date is not ISO 8601 basic: %r" % amz_date, details
    # timegm, not mktime: the header is UTC and the runner's own zone must not move the comparison
    skew = abs(calendar.timegm(sent) - time.time())
    if skew > 900:
        return False, "the request is %.0fs away from now (SigV4 allows 15 minutes)" % skew, details

    if date_stamp != amz_date[:8]:
        return False, "the credential date %s does not match x-amz-date %s" % (date_stamp, amz_date), details

    names = signed_headers.split(";")
    for required in ("host", "x-amz-date"):
        if required not in names:
            return False, "%s is not in SignedHeaders" % required, details
    token = headers.get("x-amz-security-token", "")
    if token:
        if "x-amz-security-token" not in names:
            return False, "x-amz-security-token was sent but not signed", details
    else:
        if "x-amz-security-token" in names:
            return False, "x-amz-security-token is signed but was not sent", details

    canonical_headers = ""
    for name in names:
        if name not in headers:
            return False, "SignedHeaders lists %s, which was not sent" % name, details
        canonical_headers += "%s:%s\n" % (name, " ".join(headers[name].split()))
    payload_hash = headers.get("x-amz-content-sha256") or hashlib.sha256(body).hexdigest()

    canonical_request = "\n".join([
        method, path, canonical_query(query), canonical_headers, signed_headers, payload_hash,
    ])
    scope = "%s/%s/%s/aws4_request" % (date_stamp, region, service)
    to_sign = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (
        amz_date, scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest())

    key = sign(("AWS4" + SECRET_KEY).encode("utf-8"), date_stamp)
    key = sign(key, region)
    key = sign(key, service)
    key = sign(key, "aws4_request")
    expected = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    details.update({"canonicalRequest": canonical_request, "expected": expected, "sent": signature})
    if not hmac.compare_digest(expected, signature):
        return False, "signature mismatch", details
    return True, "", details


def scenario():
    path = os.path.join(STATE, "respond.json")
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {"status": 200, "body": "{}"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        # readiness probe only
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        raw_path, _, query = self.path.partition("?")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        headers = {name.lower(): value for name, value in self.headers.items()}

        # the reply is read first: it also says which region the signature should have been scoped to
        reply = scenario()
        ok, reason, details = verify("POST", raw_path, query, headers, body,
                                     reply.get("expectRegion", REGION))
        function = ""
        prefix = "/2015-03-31/functions/"
        if raw_path.startswith(prefix) and raw_path.endswith("/invocations"):
            function = unquote(raw_path[len(prefix):-len("/invocations")])

        record = {
            "method": "POST",
            "path": raw_path,
            "rawQuery": query,
            "function": function,
            "headers": headers,
            "body": body.decode("utf-8", "replace"),
            "bodyBytes": len(body),
            "signatureOk": ok,
            "signatureProblem": reason,
        }
        if not ok:
            record["canonicalRequest"] = details.get("canonicalRequest", "")
        with open(WIRE, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

        if not ok:
            self._json(403, json.dumps({
                "__type": "InvalidSignatureException",
                "message": "The request signature we calculated does not match the signature you provided. "
                           "Check your AWS Secret Access Key and signing method. (" + reason + ")",
            }))
            return

        delay = reply.get("delay") or 0
        if delay:
            time.sleep(delay)

        status = reply.get("status", 200)
        payload = reply.get("body", "{}")
        if not isinstance(payload, str):
            payload = json.dumps(payload)
        encoded = payload.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("x-amzn-RequestId", reply.get("requestId", "8f1c1d2b-0000-4000-8000-000000000000"))
        for name, value in (reply.get("headers") or {}).items():
            self.send_header(name, value)
        if reply.get("logResult") is not None:
            self.send_header("X-Amz-Log-Result", base64.b64encode(
                str(reply["logResult"]).encode("utf-8")).decode("ascii"))
        length_header = reply.get("contentLength")
        self.send_header("Content-Length", str(len(encoded) if length_header is None else length_header))
        self.end_headers()
        self.wfile.write(encoded)
        self.wfile.flush()

    def _json(self, status, text):
        encoded = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        self.wfile.flush()


def main():
    port = int(sys.argv[1])
    os.makedirs(STATE, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("fake lambda on %d" % port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
