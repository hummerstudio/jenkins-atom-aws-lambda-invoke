# aws-lambda-invoke

Invokes one AWS Lambda function and returns what it answered. Ported from the `invokeLambda` step of the
[pipeline-aws](https://plugins.jenkins.io/pipeline-aws/) plugin (13,251 installs, last release 0.5 months ago).

```
awsLambdaInvoke function: 'resize-images', payload: [bucket: 'in', key: 'a.jpg']
```

## What the plugin does, and what this atom copies

`InvokeLambdaStep.Execution#run` builds one `InvokeRequest` and lets the AWS SDK send it:

- `functionName` from the step's first argument (a bare name, a version/alias-qualified name, or a full ARN);
- `payload` only when a payload was given, as UTF-8 bytes;
- `LogType.TAIL` always, which is `X-Amz-Log-Type: Tail` on the wire and a base64 `LogResult` on the way back;
- the SDK's default invocation type (`RequestResponse`), so the step waits for the answer;
- a non-null `X-Amz-Function-Error` becomes an exception whose message is the returned payload;
- otherwise the payload is parsed as JSON and returned, unless `returnValueAsString` is set, in which case the raw
  string is returned;
- the `LogResult` is base64-decoded and appended to the build log.

So the atom is one signed POST:

```
POST /2015-03-31/functions/<function>/invocations
X-Amz-Log-Type: Tail
Content-Type: application/json        (only when a payload is sent)
```

with SigV4 scoped to `lambda` in the step's region. The signature is written out in `AwsSigner.java` rather than
pulled from the SDK: it is a handful of HMACs, and keeping the SDK out means the atom runs on an agent with nothing
installed. The `FunctionName` is one path segment: unreserved characters and `:` stay as they are (AWS documents ARNs
written out in the path), everything else is percent-encoded, so a name with a space or a slash cannot quietly address a
different function.

## Deliberate differences from the plugin

- **The payload is required to be JSON.** The plugin passes whatever the step was given; AWS requires a JSON body, so a
  payload that does not parse fails the step here (`40003`) instead of being rejected by the service with a 400.
- **A non-JSON answer fails unless you asked for text.** The plugin's `JsonUtils.fromString` throws on a text answer;
  this atom reports that as `40008` naming the function, and `returnValueAsString=true` accepts it. `payloadType` says
  which one happened.
- **The response is read as bytes and compared.** `payloadBytes` is the length that arrived, so a truncated body is
  visible in the outputs (and a cut JSON answer fails to parse rather than passing as a short string).
- **The log tail is an output**, `logTail`, not only a console line.
- **AWS is not called when the inputs are unusable** -- no function, no region, no credentials, non-JSON payload: the
  step fails before the request, and the checks assert that nothing was sent.
- **Error classification.** `40005` a rejected signature or credential (with the clock hint, because SigV4 is
  time-sensitive), `40006` no such function, `40007` the function itself reported `X-Amz-Function-Error`,
  `50201` AWS failed, `50202`/`50203` network or timeout.
- Credentials are inputs (bind an AWS credential); the environment fallbacks the SDK used (`AWS_REGION`,
  `AWS_DEFAULT_REGION`) are honoured for the region only -- an agent should not silently pick up ambient keys.

## Not ported

- `withAWS` / `awsIdentity` and the other steps in the plugin that change the *context* for later steps (block
  semantics: an atom is one process, it cannot set globals for the next step).
- S3 (`s3Upload`, `s3Copy`, `s3Delete`, `s3Download`, `s3FindFiles`, `s3PresignUrl`), CloudFormation and CodeDeploy:
  already covered by `s3-upload`, `aws-cloudformation`, `aws-codedeploy`.
- `waitLamdba` / `EBWaitOn*` / `cfn` polling: a wait loop is a job-model behaviour, not a step.
- `invokeLambda` with `invocationType: Event` (fire and forget): the plugin has no such option either.

## Verification

`tools/check.py` (27 checks) drives the atom exactly the way the runner does -- `input.json`, `.secrets.json`,
`output.json` -- against `tools/fake_lambda.py`, which **recomputes the SigV4 signature from the request that arrived**
(canonical request, string to sign, four HMACs, its own implementation), refuses a request whose signature, credential
scope, date or signed-header list is wrong, and records every request. The checks then assert on that record: the path,
`X-Amz-Log-Type: Tail`, `Content-Type`, the payload bytes byte for byte, the function name after decoding, the session
token being signed. Failure paths have their own assertions: a function error, a missing function, a rejected
signature, a 503, a truncated body, invalid JSON, missing inputs (asserting no request was sent), a timeout, and that
`.secrets.json` is deleted and does not leak into the outputs.

`tools/mutations.py` plants 25 bugs in the real source one at a time and rebuilds each: wrong API version, missing
`/invocations`, `LogType` not Tail, wrong content type, `s3` in the credential scope, an unsigned session token, the
payload hash of an empty body, `localhost` as the signed host, the payload hash missing from the canonical request, a
non-JSON payload sent anyway, a function error counted as success, 404 reported as a credential problem,
`returnValueAsString` ignored, the log tail left base64, the wrong request-id header, an unencoded function name, an
empty payload turned into `{}`, a trimmed payload, credentials not required, the region hardcoded, a non-200 treated as
success, latin-1 decoding. All 25 have to be caught; a survivor is a hole in the suite.

`./tools/smoke.sh` builds the atom and runs the checks, and it is what CI runs.

## Inputs / outputs

Inputs: `function`, `payload`, `returnValueAsString`, `region`, `endpoint` (tests / PrivateLink), `timeoutSeconds`,
`accessKey`, `secretKey`, `sessionToken`.

Outputs: `payload`, `payloadType` (`json` or `text`), `payloadBytes`, `functionError`, `statusCode`,
`executedVersion`, `requestId`, `logTail`, `region`.
