#!/usr/bin/env python3
"""Plant one bug at a time in the atom and prove the checks catch it.

A green suite means nothing if it stays green for a broken atom. Each mutation is one textual change to the real
source, rebuilt into its own jar, and the named check must then fail. A survivor is a hole in the suite -- and for a
signer, the dangerous survivor is one the fake service would not have noticed either.

    python3 tools/mutations.py
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent.parent
CODE = "aws-lambda-invoke"
PACKAGE = HERE / "src" / "main" / "java" / "com" / "jenkinschina" / "atom" / "awslambdainvoke"
ATOM = PACKAGE / "AwsLambdaInvokeAtom.java"
SIGNER = PACKAGE / "AwsSigner.java"

MUTATIONS = [
    ('the API version is off by a day', ATOM, 'API_VERSION = "/2015-03-31/functions/"', 'API_VERSION = "/2015-03-30/functions/"', 'invoke.ok.json'),
    ('the path has no invocations suffix', ATOM, 'API_VERSION + encode(function) + "/invocations"', 'API_VERSION + encode(function)', 'invoke.ok.json'),
    ('the log type is None instead of Tail', ATOM, 'signed.put("x-amz-log-type", "Tail");', 'signed.put("x-amz-log-type", "None");', 'invoke.ok.json'),
    ('the body is announced as text/plain', ATOM, 'signed.put("content-type", "application/json");', 'signed.put("content-type", "text/plain");', 'invoke.ok.json'),
    ('the credential scope names s3', ATOM, 'LAMBDA_SERVICE = "lambda";', 'LAMBDA_SERVICE = "s3";', 'invoke.ok.json'),
    ('the session token is sent but not signed', SIGNER, 'canonical.put("x-amz-security-token", sessionToken);', 'if (false) canonical.put("x-amz-security-token", sessionToken);', 'invoke.session.token'),
    ('the session token is not sent at all', SIGNER, 'headers.put("X-Amz-Security-Token", sessionToken);', 'headers.put("X-Amz-Security-Token", "");', 'invoke.session.token'),
    ('the payload hash is computed over an empty body', SIGNER, 'String payloadHash = hex(sha256(payload.getBytes(StandardCharsets.UTF_8)));', 'String payloadHash = hex(sha256(new byte[0]));', 'invoke.ok.json'),
    ('the host is signed as localhost', SIGNER, 'canonical.put("host", host);', 'canonical.put("host", "localhost");', 'invoke.ok.json'),
    ('the canonical request is signed without the payload hash', SIGNER, '+ payloadHash;', '+ "";', 'invoke.ok.json'),
    ('a payload that is not JSON is sent anyway', ATOM, '                Json.parse(body);', '                Json.parse("{}");', 'invoke.invalid.payload.json'),
    ('a function error counts as a success', ATOM, '        if (!functionError.isEmpty()) {', '        if (false) {', 'invoke.function.error'),
    ('a missing function is reported as a bad credential', ATOM, '        if (status == 404 || code.contains("ResourceNotFound")) {', '        if (false) {', 'invoke.notfound'),
    ('returnValueAsString is ignored', ATOM, '        if (!asString) {', '        if (true) {', 'invoke.text.accepted'),
    ('a text answer is accepted when JSON was asked for', ATOM, '                Json.parse(text);\n                type = "json";', '                Json.parse("{}");\n                type = "json";', 'invoke.payload.text.rejected'),
    ('the log tail is the raw base64', ATOM, '            return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);', '            return value;', 'invoke.log.tail.decoded'),
    ('the request id comes from the wrong header', ATOM, 'header(reply, "x-amzn-requestid")', 'header(reply, "x-amz-request-id")', 'invoke.request.id.passthrough'),
    ('the executed version is never read', ATOM, 'header(reply, "x-amz-executed-version")', 'header(reply, "x-amz-version")', 'invoke.ok.json'),
    ('the function name goes into the path unencoded', ATOM, 'String path = API_VERSION + encode(function) + "/invocations";', 'String path = API_VERSION + function + "/invocations";', 'invoke.name.encoded'),
    ('an empty payload is sent as an empty object', ATOM, 'String body = payload == null ? "" : payload;', 'String body = payload == null || payload.isEmpty() ? "{}" : payload;', 'invoke.empty.payload'),
    ('the payload is trimmed before it is sent', ATOM, 'String body = payload == null ? "" : payload;', 'String body = payload == null ? "" : payload.trim();', 'invoke.payload.whitespace'),
    ('credentials are not required', ATOM, '        if (accessKey.isEmpty() || secretKey.isEmpty()) {', '        if (false) {', 'invoke.input.credentials.required'),
    ('the signature is always scoped to us-east-1', ATOM, 'new AwsSigner(accessKey, secretKey, sessionToken, region, LAMBDA_SERVICE)', 'new AwsSigner(accessKey, secretKey, sessionToken, "us-east-1", LAMBDA_SERVICE)', 'invoke.region.from.environment'),
    ('a non-200 answer is treated as a success', ATOM, '        if (reply.statusCode() != 200) {', '        if (false) {', 'invoke.server.error'),
    ('the response is decoded as latin-1', ATOM, 'String text = new String(received, StandardCharsets.UTF_8);', 'String text = new String(received, StandardCharsets.ISO_8859_1);', 'invoke.payload.exact.bytes'),
]


def sdk_jar():
    env = os.environ.get("SDK_JAR")
    if env:
        return env
    for root in (HERE.parent / "jenkins-atom-sdk", HERE / "jenkins-atom-sdk"):
        candidates = sorted((root / "target").glob("jenkins-atom-sdk-*.jar"))
        if candidates:
            return str(candidates[-1])
    raise SystemExit("build the SDK first: cd ../jenkins-atom-sdk && ./build.sh")


def build(tree):
    env = dict(os.environ)
    env["SDK_JAR"] = sdk_jar()
    proc = subprocess.run(["bash", "build.sh"], cwd=tree, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        return None, proc.stderr[-1500:]
    return tree / "dist" / CODE / (CODE + ".jar"), proc.stdout


def main():
    failures = 0
    for index, (name, source_file, old, new, case) in enumerate(MUTATIONS, 1):
        tree = pathlib.Path(tempfile.mkdtemp(prefix="lambda-mut-")) / "atom"
        shutil.copytree(HERE, tree, ignore=shutil.ignore_patterns("dist", ".git", "__pycache__"))
        source = tree / source_file.relative_to(HERE)
        text = source.read_text(encoding="utf-8")
        if old not in text:
            print("SKIP  %s: the mutation no longer matches the source" % name)
            failures += 1
            continue
        source.write_text(text.replace(old, new, 1), encoding="utf-8")
        jar, output = build(tree)
        if jar is None:
            print("SKIP  %s: the mutated atom does not build: %s" % (name, output))
            failures += 1
            continue
        proc = subprocess.run([sys.executable, "tools/check.py", case, "--jar", str(jar)],
                              cwd=tree, capture_output=True, text=True)
        if proc.returncode == 0:
            print("SURVIVED %-2d %s (case %s stayed green)" % (index, name, case))
            failures += 1
        else:
            print("caught   %-2d %s" % (index, name))
    print("\n%d/%d mutations caught" % (len(MUTATIONS) - failures, len(MUTATIONS)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
