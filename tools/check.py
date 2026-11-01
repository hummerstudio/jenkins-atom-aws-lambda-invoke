#!/usr/bin/env python3
"""Behaviour checks for the aws-lambda-invoke atom.

Each check drives the atom the way the runner does -- input.json in, output.json out, secrets in .secrets.json -- and
points it at tools/fake_lambda.py, which recomputes the SigV4 signature from the request that arrived and refuses the
call when the two disagree. So "success" here means: a request AWS would have accepted, with the path, headers and body
the Invoke API expects, and an answer the atom read back byte for byte.

    python3 tools/check.py                     # every check
    python3 tools/check.py function.error      # only checks whose name contains that
    python3 tools/check.py invoke.ok --jar X   # run a mutated build against the packed jar
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
JAR = os.path.join(REPO, "dist", "aws-lambda-invoke", "aws-lambda-invoke.jar")
JAVA = os.path.join(os.environ.get("JAVA_HOME", "/Users/tangming/tools/jdk-21.0.12.1+1/Contents/Home"),
                    "bin", "java")
TASK = json.load(open(os.path.join(REPO, "task.json"), encoding="utf-8"))

ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
SESSION_TOKEN = "session/token+EXAMPLE"
REGION = "us-east-1"

CHECKS = []
STATE = tempfile.mkdtemp(prefix="fake-lambda-state-")
WIRE = os.path.join(STATE, "wire.log")


def check(name):
    def register(fn):
        CHECKS.append((name, fn))
        return fn
    return register


# --------------------------------------------------------------------------- the fake service

def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


PORT = free_port()
ENDPOINT = "http://127.0.0.1:%d" % PORT


def start_server():
    open(WIRE, "w").close()
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "fake_lambda.py"), str(PORT), STATE, WIRE],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.05)
    raise SystemExit("the fake Lambda did not start on %d" % PORT)


def scenario(**fields):
    reply = {"status": 200, "body": "{}"}
    reply.update(fields)
    with open(os.path.join(STATE, "respond.json"), "w", encoding="utf-8") as handle:
        json.dump(reply, handle)


def wire():
    records = []
    try:
        with open(WIRE, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    except OSError:
        pass
    return records


# --------------------------------------------------------------------------- the runner's contract

def base_input(**overrides):
    data = {name: spec.get("default", "") for name, spec in TASK["input"].items()}
    data.update({"JOB_NAME": "deploy", "BUILD_NUMBER": "7", "BUILD_STATUS": "SUCCESS"})
    data.update(overrides)
    return data


def run(overrides, secrets=None, env_extra=None, drop=(), timeout=120):
    open(WIRE, "w").close()
    directory = tempfile.mkdtemp(prefix="lambda-check-")
    data = base_input(**overrides)
    for name in drop:
        data.pop(name, None)
    json.dump(data, open(os.path.join(directory, "input.json"), "w", encoding="utf-8"), ensure_ascii=False)
    if secrets is None:
        secrets = {"accessKey": ACCESS_KEY, "secretKey": SECRET_KEY}
    if secrets:
        json.dump(secrets, open(os.path.join(directory, ".secrets.json"), "w", encoding="utf-8"))
    env = dict(os.environ)
    for stale in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        env.pop(stale, None)
    env.update({"atom_data_dir": directory, "atom_data_input": "input.json", "atom_data_output": "output.json",
                "atom_workspace": directory})
    env.update(env_extra or {})
    proc = subprocess.run([JAVA, "-cp", JAR, "com.jenkinschina.atom.sdk.AtomRunner"], cwd=directory, env=env,
                          capture_output=True, text=True, timeout=timeout)
    out = os.path.join(directory, "output.json")
    result = json.load(open(out, encoding="utf-8")) if os.path.exists(out) else {}
    values = {key: node.get("value") for key, node in (result.get("data") or {}).items()}
    return result, values, proc, directory


def expect_error(result, code):
    assert result.get("status") == "error", "expected an error, got %s: %s" % (result.get("status"),
                                                                              result.get("message"))
    assert result.get("errorCode") == code, "expected error %s, got %s: %s" % (code, result.get("errorCode"),
                                                                              result.get("message"))


def credentials():
    return {"accessKey": ACCESS_KEY, "secretKey": SECRET_KEY, "sessionToken": ""}


# --------------------------------------------------------------------------- checks

@check("invoke.ok.json")
def _():
    scenario(body='{"ok": true, "count": 3}', headers={"x-amz-executed-version": "42"},
             logResult="START RequestId: 1\nEND RequestId: 1\n")
    result, values, proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT,
                                      "payload": '{"a": 1}'}, credentials())
    assert result.get("status") == "success", result.get("message")
    assert values["payload"] == '{"ok": true, "count": 3}', values["payload"]
    assert values["payloadType"] == "json", values["payloadType"]
    assert values["statusCode"] == "200", values["statusCode"]
    assert values["executedVersion"] == "42", values["executedVersion"]
    assert values["functionError"] == "", values["functionError"]
    records = wire()
    assert len(records) == 1, records
    record = records[0]
    assert record["signatureOk"], record["signatureProblem"]
    assert record["path"] == "/2015-03-31/functions/my-function/invocations", record["path"]
    assert record["headers"]["x-amz-log-type"] == "Tail", record["headers"]
    assert record["headers"]["content-type"] == "application/json", record["headers"]
    assert record["body"] == '{"a": 1}', record["body"]


@check("invoke.payload.exact.bytes")
def _():
    answer = '{"text": "第一行\\n第二行 \\"quoted\\"", "size": 2}'
    scenario(body=answer)
    result, values, _proc, _dir = run({"function": "echo", "region": REGION, "endpoint": ENDPOINT,
                                       "payload": '{"say": "你好"}'}, credentials())
    assert result.get("status") == "success", result.get("message")
    assert values["payload"] == answer, repr(values["payload"])
    record = wire()[0]
    assert record["body"] == '{"say": "你好"}', record["body"]
    assert record["headers"]["content-length"] == str(len('{"say": "你好"}'.encode("utf-8"))), record["headers"]


@check("invoke.payload.whitespace")
def _():
    # the payload is the caller's document: leading and trailing whitespace is part of the bytes that get signed
    request = '  {"padded": true}\n'
    scenario(body='{"ok": true}')
    result, _values, _proc, _dir = run({"function": "echo", "region": REGION, "endpoint": ENDPOINT,
                                        "payload": request}, credentials())
    assert result.get("status") == "success", result.get("message")
    assert wire()[0]["body"] == request, repr(wire()[0]["body"])


@check("invoke.payload.text.rejected")
def _():
    scenario(body="plain text, not JSON")
    result, values, _proc, _dir = run({"function": "echo", "region": REGION, "endpoint": ENDPOINT,
                                       "payload": "{}"}, credentials())
    expect_error(result, 40008)
    assert "returnValueAsString" in result.get("message", ""), result.get("message")


@check("invoke.text.accepted")
def _():
    scenario(body="plain text, not JSON")
    result, values, _proc, _dir = run({"function": "echo", "region": REGION, "endpoint": ENDPOINT,
                                       "payload": "{}", "returnValueAsString": "true"}, credentials())
    assert result.get("status") == "success", result.get("message")
    assert values["payload"] == "plain text, not JSON", values["payload"]
    assert values["payloadType"] == "text", values["payloadType"]


@check("invoke.text.recognises.json")
def _():
    scenario(body='{"looks": "structured"}')
    result, values, _proc, _dir = run({"function": "echo", "region": REGION, "endpoint": ENDPOINT,
                                       "payload": "{}", "returnValueAsString": "true"}, credentials())
    assert values["payloadType"] == "json", values["payloadType"]


@check("invoke.function.error")
def _():
    scenario(status=200, body='{"errorMessage": "boom", "errorType": "RuntimeError"}',
             headers={"x-amz-function-error": "Unhandled"})
    result, _values, _proc, _dir = run({"function": "broken", "region": REGION, "endpoint": ENDPOINT,
                                        "payload": "{}"}, credentials())
    expect_error(result, 40007)
    message = result.get("message", "")
    assert "broken" in message and "Unhandled" in message and "boom" in message, message


@check("invoke.notfound")
def _():
    scenario(status=404, body='{"message": "Function not found: arn:aws:lambda:us-east-1:1:function:nope", '
                              '"__type": "ResourceNotFoundException"}')
    result, _values, _proc, _dir = run({"function": "nope", "region": REGION, "endpoint": ENDPOINT},
                                       credentials())
    expect_error(result, 40006)
    assert "no such function" in result.get("message", ""), result.get("message")


@check("invoke.access.denied")
def _():
    scenario(body='{"ok": true}')
    bad = {"accessKey": ACCESS_KEY, "secretKey": "not-the-secret"}
    result, _values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                       bad)
    expect_error(result, 40005)
    assert "signature" in result.get("message", "").lower() or "403" in result.get("message", ""), \
        result.get("message")
    assert wire()[0]["signatureOk"] is False, wire()[0]


@check("invoke.server.error")
def _():
    scenario(status=503, body='{"message": "Service Unavailable"}')
    result, _values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                       credentials())
    expect_error(result, 50201)


@check("invoke.truncated.body")
def _():
    # the service declares fewer bytes than it writes: java.net.http reads exactly what was declared, so a JSON answer
    # arrives cut in half and must fail as unreadable rather than pass through
    scenario(body='{"complete": true}', contentLength=6)
    result, _values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                       credentials())
    expect_error(result, 40008)
    assert "not JSON" in result.get("message", ""), result.get("message")


@check("invoke.arn.in.path")
def _():
    arn = "arn:aws:lambda:us-east-1:123456789012:function:my-function"
    scenario(body='{"ok": true}')
    result, _values, _proc, _dir = run({"function": arn, "region": REGION, "endpoint": ENDPOINT}, credentials())
    assert result.get("status") == "success", result.get("message")
    record = wire()[0]
    assert record["function"] == arn, record["function"]
    assert record["path"] == "/2015-03-31/functions/" + arn + "/invocations", record["path"]
    assert record["signatureOk"], record["signatureProblem"]


@check("invoke.name.encoded")
def _():
    scenario(body='{"ok": true}')
    name = "weird name/with#bits"
    result, _values, _proc, _dir = run({"function": name, "region": REGION, "endpoint": ENDPOINT}, credentials())
    assert result.get("status") == "success", result.get("message")
    record = wire()[0]
    assert record["function"] == name, record["function"]
    assert "%20" in record["path"] and "%2F" in record["path"] and "%23" in record["path"], record["path"]
    assert " " not in record["path"], record["path"]
    assert record["signatureOk"], record["signatureProblem"]


@check("invoke.empty.payload")
def _():
    scenario(body='{"ok": true}')
    result, _values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                       credentials())
    assert result.get("status") == "success", result.get("message")
    record = wire()[0]
    assert record["bodyBytes"] == 0, record["bodyBytes"]
    assert "content-type" not in record["headers"], record["headers"]
    assert record["signatureOk"], record["signatureProblem"]


@check("invoke.invalid.payload.json")
def _():
    scenario(body='{"ok": true}')
    result, _values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT,
                                        "payload": "{not json"}, credentials())
    expect_error(result, 40003)
    assert wire() == [], "a request was sent for a payload that is not JSON"


@check("invoke.input.function.required")
def _():
    scenario(body='{"ok": true}')
    result, _values, _proc, _dir = run({"region": REGION, "endpoint": ENDPOINT}, credentials())
    expect_error(result, 40001)
    assert wire() == [], wire()


@check("invoke.input.region.required")
def _():
    scenario(body='{"ok": true}')
    result, _values, _proc, _dir = run({"function": "my-function", "endpoint": ENDPOINT}, credentials())
    expect_error(result, 40002)
    assert wire() == [], wire()


@check("invoke.region.from.environment")
def _():
    scenario(body='{"ok": true}', expectRegion="eu-west-1")
    result, values, _proc, _dir = run({"function": "my-function", "endpoint": ENDPOINT}, credentials(),
                                      env_extra={"AWS_REGION": "eu-west-1"})
    assert result.get("status") == "success", result.get("message")
    assert values["region"] == "eu-west-1", values["region"]
    record = wire()[0]
    assert "eu-west-1" in record["headers"]["authorization"], record["headers"]["authorization"]


@check("invoke.input.credentials.required")
def _():
    scenario(body='{"ok": true}')
    result, _values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                       secrets={})
    expect_error(result, 40004)
    assert wire() == [], wire()


@check("invoke.session.token")
def _():
    scenario(body='{"ok": true}')
    result, _values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                       {"accessKey": ACCESS_KEY, "secretKey": SECRET_KEY,
                                        "sessionToken": SESSION_TOKEN})
    assert result.get("status") == "success", result.get("message")
    record = wire()[0]
    assert record["headers"]["x-amz-security-token"] == SESSION_TOKEN, record["headers"]
    assert "x-amz-security-token" in record["headers"]["authorization"], record["headers"]["authorization"]
    assert record["signatureOk"], record["signatureProblem"]


@check("invoke.log.tail.decoded")
def _():
    log = "START RequestId: 1 Version: $LATEST\nhello from the function\nEND RequestId: 1\n"
    scenario(body='{"ok": true}', logResult=log)
    result, values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                       credentials())
    assert result.get("status") == "success", result.get("message")
    assert values["logTail"] == log, repr(values["logTail"])


@check("invoke.log.tail.invalid")
def _():
    scenario(body='{"ok": true}', headers={"X-Amz-Log-Result": "!!!not base64!!!"})
    result, values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                      credentials())
    assert result.get("status") == "success", result.get("message")
    assert values["logTail"] == "", repr(values["logTail"])


@check("invoke.log.tail.absent")
def _():
    scenario(body='{"ok": true}')
    result, values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                       credentials())
    assert values.get("logTail") == "", repr(values.get("logTail"))


@check("invoke.big.payload")
def _():
    # 300 KB of JSON: the body must go out whole and come back whole
    answer = json.dumps({"blob": "x" * 300000})
    request = json.dumps({"blob": "y" * 300000})
    scenario(body=answer)
    result, values, _proc, _dir = run({"function": "big", "region": REGION, "endpoint": ENDPOINT,
                                        "payload": request}, credentials(), timeout=180)
    assert result.get("status") == "success", result.get("message")
    assert values["payload"] == answer, "the response was cut: %d bytes" % len(values["payload"])
    record = wire()[0]
    assert record["body"] == request, "the request was cut: %d bytes" % record["bodyBytes"]
    assert record["signatureOk"], record["signatureProblem"]


@check("invoke.request.id.passthrough")
def _():
    scenario(body='{"ok": true}', requestId="1234abcd-0000-4000-8000-000000000001")
    result, values, _proc, _dir = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                       credentials())
    assert values["requestId"] == "1234abcd-0000-4000-8000-000000000001", values["requestId"]


@check("invoke.secrets.removed")
def _():
    scenario(body='{"ok": true}')
    result, values, _proc, directory = run({"function": "my-function", "region": REGION, "endpoint": ENDPOINT},
                                           credentials())
    assert result.get("status") == "success", result.get("message")
    assert not os.path.exists(os.path.join(directory, ".secrets.json")), ".secrets.json was left behind"
    blob = json.dumps(values, ensure_ascii=False)
    assert SECRET_KEY not in blob, "the secret leaked into the outputs"


@check("invoke.timeout")
def _():
    scenario(body='{"ok": true}', delay=8)
    started = time.time()
    result, _values, _proc, _dir = run({"function": "slow", "region": REGION, "endpoint": ENDPOINT,
                                         "timeoutSeconds": "5"}, credentials(), timeout=60)
    expect_error(result, 50203)
    assert time.time() - started < 20, "the atom waited far past its timeout"


def main():
    global JAR
    args = [a for a in sys.argv[1:]]
    if "--jar" in args:
        index = args.index("--jar")
        JAR = os.path.abspath(args[index + 1])
        del args[index:index + 2]
    needle = args[0] if args else ""
    if not os.path.exists(JAR):
        raise SystemExit("build the atom first: ./build.sh (%s is missing)" % JAR)
    server = start_server()
    passed = failed = 0
    try:
        for name, fn in CHECKS:
            if needle and needle not in name:
                continue
            try:
                fn()
                print("ok   %s" % name)
                passed += 1
            except AssertionError as e:
                print("FAIL %s: %s" % (name, e))
                failed += 1
            except Exception as e:  # noqa: BLE001 - a crash is a failure, with the type in the line
                print("FAIL %s: %s: %s" % (name, type(e).__name__, e))
                failed += 1
    finally:
        server.terminate()
        server.wait(timeout=10)
        shutil.rmtree(STATE, ignore_errors=True)
    print("\n%d/%d checks passed" % (passed, passed + failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
