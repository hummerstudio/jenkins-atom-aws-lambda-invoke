package com.jenkinschina.atom.awslambdainvoke;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import com.jenkinschina.atom.sdk.Json;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Invokes one AWS Lambda function and returns what it answered.
 *
 * <p>Ported from the {@code invokeLambda} step of the pipeline-aws plugin. That plugin builds an AWS SDK
 * {@code InvokeRequest} with the function name, the payload and {@code LogType.TAIL}, lets the SDK sign it, and then
 * either parses the response payload as JSON or hands back the raw string; a non-null {@code FunctionError} becomes an
 * exception carrying that payload. There is no state and no second call, so the whole step is one signed POST:
 * {@code POST /2015-03-31/functions/<name>/invocations} with {@code X-Amz-Log-Type: Tail}.
 *
 * <p>The SDK is not shipped: the request is one HTTP call and the signature is a few HMACs. What the SDK did silently
 * is written down instead -- the canonical request, which headers are signed, the payload hash -- so a wrong signature
 * is a readable failure and the smoke test can recompute it independently.
 *
 * <p>Differences from the plugin (all in the README): the response body is read as bytes, so the {@code Content-Length}
 * the service declared is compared with what arrived; a payload that is not JSON fails the step by name instead of
 * being passed on as text (set {@code returnValueAsString} to accept text); the decoded {@code LogResult} is an output,
 * not only a console line.
 */
public class AwsLambdaInvokeAtom implements AtomTask {

    private static final String LAMBDA_SERVICE = "lambda";
    private static final String API_VERSION = "/2015-03-31/functions/";

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        String function = context.getParam("function", "").trim();
        String payload = context.getParam("payload", "");
        boolean asString = context.getBooleanParam("returnValueAsString", false);
        String region = context.getParam("region", "").trim();
        String endpoint = context.getParam("endpoint", "").trim();
        int timeoutSeconds = Math.max(5, Math.min(context.getIntParam("timeoutSeconds", 120), 1800));
        Duration timeout = Duration.ofSeconds(timeoutSeconds);

        if (function.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40001,
                    "function is required: a function name or a full ARN (e.g. my-function or "
                            + "arn:aws:lambda:us-east-1:123456789012:function:my-function)");
        }
        if (region.isEmpty()) {
            region = env("AWS_REGION");
        }
        if (region.isEmpty()) {
            region = env("AWS_DEFAULT_REGION");
        }
        if (region.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40002,
                    "region is required: the signature is scoped to a region (AWS_REGION is not set on the agent)");
        }

        String accessKey = secret(context, "accessKey");
        String secretKey = secret(context, "secretKey");
        String sessionToken = secret(context, "sessionToken");
        if (accessKey.isEmpty() || secretKey.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40004,
                    "accessKey and secretKey are required (bind an AWS credential or set the two secrets)");
        }

        // The plugin sends the payload verbatim as the request body and lets the function decide what it means. It is
        // JSON by contract, so a body that is not JSON is caught here rather than by Lambda with a 400.
        String body = payload == null ? "" : payload;
        if (!body.isEmpty()) {
            try {
                Json.parse(body);
            } catch (RuntimeException e) {
                return AtomResult.error(ErrorType.USER, 40003,
                        "payload is not valid JSON (" + e.getMessage() + "); send a JSON document or leave it empty");
            }
        }

        String base = endpoint.isEmpty()
                ? "https://lambda." + region + ".amazonaws.com"
                : endpoint.replaceAll("/+$", "");
        String host = URI.create(base).getAuthority();
        String path = API_VERSION + encode(function) + "/invocations";

        Map<String, String> signed = new LinkedHashMap<>();
        signed.put("x-amz-log-type", "Tail");
        if (!body.isEmpty()) {
            signed.put("content-type", "application/json");
        }
        Map<String, String> headers = new AwsSigner(accessKey, secretKey, sessionToken, region, LAMBDA_SERVICE)
                .headers("POST", path, "", body, host,
                        signed);
        headers.put("Accept", "application/json");

        context.group("invoke " + function);
        context.log("POST " + base + path + " (region " + region + ", payload "
                + body.getBytes(StandardCharsets.UTF_8).length + " bytes, LogType Tail)");

        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        headers.forEach(request::header);

        HttpResponse<byte[]> reply;
        try {
            reply = HttpClient.newBuilder().connectTimeout(timeout).build()
                    .send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (HttpTimeoutException e) {
            return AtomResult.error(ErrorType.THIRD_PART, 50203,
                    "Lambda did not answer within " + timeoutSeconds + "s for " + function
                            + " (the function may still be running; check its timeout)");
        } catch (IOException e) {
            return AtomResult.error(ErrorType.THIRD_PART, 50202,
                    "cannot reach " + host + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        byte[] received = reply.body() == null ? new byte[0] : reply.body();
        // Read-back: the body is bytes, so the length the service declared can be compared with the length that
        // arrived. A truncated payload that parses would otherwise look like a successful invocation.
        String declared = header(reply, "content-length");
        if (!declared.isEmpty()) {
            long expected;
            try {
                expected = Long.parseLong(declared.trim());
            } catch (NumberFormatException e) {
                return AtomResult.error(ErrorType.THIRD_PART, 50204,
                        "the response declares Content-Length '" + declared + "', which is not a number");
            }
            if (expected != received.length) {
                return AtomResult.error(ErrorType.THIRD_PART, 40010,
                        "the response declared " + expected + " bytes but " + received.length + " arrived for "
                                + function);
            }
        }

        String text = new String(received, StandardCharsets.UTF_8);
        String functionError = header(reply, "x-amz-function-error");
        String requestId = header(reply, "x-amzn-requestid");
        String executedVersion = header(reply, "x-amz-executed-version");
        String logTail = decodeLogResult(header(reply, "x-amz-log-result"));

        if (reply.statusCode() != 200) {
            return apiFailure(reply.statusCode(), text, function);
        }
        if (!functionError.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40007,
                    "the function " + function + " reported " + functionError + ": " + shorten(text)
                            + " (the invocation itself succeeded: HTTP 200 with X-Amz-Function-Error)");
        }

        String type = "text";
        if (!asString) {
            try {
                Json.parse(text);
                type = "json";
            } catch (RuntimeException e) {
                return AtomResult.error(ErrorType.USER, 40008,
                        "the function " + function + " answered a payload that is not JSON (" + e.getMessage()
                                + "); set returnValueAsString to accept a text answer");
            }
        } else if (looksLikeJson(text)) {
            type = "json";
        }

        if (!logTail.isEmpty()) {
            context.group("log tail");
            context.log(logTail);
        }
        context.log("200 from " + function + (functionError.isEmpty() ? "" : " (" + functionError + ")")
                + ", " + received.length + " payload bytes"
                + (executedVersion.isEmpty() ? "" : ", version " + executedVersion));

        AtomResult result = AtomResult.success("invoked " + function + " ("
                + received.length + " bytes" + (executedVersion.isEmpty() ? "" : ", version " + executedVersion) + ")");
        result.data("payload", text)
                .data("payloadType", type)
                .data("payloadBytes", String.valueOf(received.length))
                .data("functionError", functionError)
                .data("statusCode", String.valueOf(reply.statusCode()))
                .data("executedVersion", executedVersion)
                .data("requestId", requestId)
                .data("logTail", logTail)
                .data("region", region);
        return result;
    }

    /**
     * A non-200 answer. Lambda's error document is JSON with {@code __type}, {@code message} or {@code Message}; the
     * interesting split is whether the caller could have avoided it (a wrong name, a rejected signature) or whether
     * AWS failed.
     */
    private AtomResult apiFailure(int status, String text, String function) {
        String code = "";
        String message = "";
        try {
            Object parsed = Json.parse(text);
            if (parsed instanceof Map) {
                Map<?, ?> map = (Map<?, ?>) parsed;
                if (map.get("__type") != null) {
                    code = String.valueOf(map.get("__type"));
                } else if (map.get("Type") != null) {
                    code = String.valueOf(map.get("Type"));
                }
                if (code.contains("#")) {
                    code = code.substring(code.lastIndexOf('#') + 1);
                }
                if (map.get("message") != null) {
                    message = String.valueOf(map.get("message"));
                } else if (map.get("Message") != null) {
                    message = String.valueOf(map.get("Message"));
                }
            }
        } catch (RuntimeException e) {
            message = shorten(text);
        }
        String detail = "Lambda answered " + status
                + (code.isEmpty() ? "" : " " + code)
                + (message.isEmpty() ? "" : ": " + shorten(message));
        boolean mine = status == 400 || status == 401 || status == 403
                || code.contains("AccessDenied") || code.contains("InvalidSignature")
                || code.contains("UnrecognizedClient") || code.contains("ExpiredToken")
                || code.contains("ResourceNotFound");
        if (!mine) {
            return AtomResult.error(ErrorType.THIRD_PART, 50201, detail);
        }
        if (status == 404 || code.contains("ResourceNotFound")) {
            return AtomResult.error(ErrorType.USER, 40006,
                    detail + " (no such function in this region: check the name, the region and the account)");
        }
        return AtomResult.error(ErrorType.USER, 40005,
                detail + " (check the AWS credential, the IAM lambda:InvokeFunction grant and the agent clock: "
                        + "SigV4 is time-sensitive)");
    }

    /**
     * One path segment of the {@code FunctionName} label: unreserved characters and {@code :} stay as they are (AWS
     * documents ARNs written out in the path), everything else is percent-encoded, so a name with a space or a slash
     * cannot change which resource is addressed.
     */
    static String encode(String value) {
        StringBuilder out = new StringBuilder();
        for (byte raw : value.getBytes(StandardCharsets.UTF_8)) {
            int c = raw & 0xff;
            boolean plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~' || c == ':';
            if (plain) {
                out.append((char) c);
            } else {
                out.append('%').append(String.format(Locale.ROOT, "%02X", c));
            }
        }
        return out.toString();
    }

    private static String header(HttpResponse<?> reply, String name) {
        return reply.headers().firstValue(name).orElse("");
    }

    /** {@code LogResult} is base64 of the last 4 KB of the function's log; the plugin decodes it and appends it. */
    private static String decodeLogResult(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        try {
            return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    private static boolean looksLikeJson(String text) {
        String trimmed = text.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}"))
                || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    private static String shorten(String text) {
        String oneLine = text == null ? "" : text.replaceAll("\\s+", " ").trim();
        return oneLine.length() <= 400 ? oneLine : oneLine.substring(0, 400) + "...";
    }

    private static String env(String name) {
        String value = System.getenv(name);
        return value == null ? "" : value.trim();
    }

    private static String secret(AtomContext context, String name) {
        String value = context.getSecret(name);
        if (value == null || value.isEmpty()) {
            value = context.getParam(name, "");
        }
        return value == null ? "" : value.trim();
    }
}
