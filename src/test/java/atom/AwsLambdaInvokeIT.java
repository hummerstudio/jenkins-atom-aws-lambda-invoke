package atom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.jenkinschina.atom.sdk.Json;
import com.jenkinschina.atom.sdk.testing.Atom;
import com.jenkinschina.atom.sdk.testing.AtomResult;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The AWS Lambda Invoke atom against {@code tools/fake_lambda.py}, which recomputes the SigV4 signature of every
 * request it receives: a wrong signer fails here the way it fails against AWS, with a 403.
 *
 * <p>The behaviour matrix is {@code tools/check.py}, kept as the fixture that defines what a correct request looks
 * like; every case it exercises is asserted here in Java.
 */
class AwsLambdaInvokeIT {

    private static final String ACCESS_KEY = "AKIDEXAMPLE";
    private static final String SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    private static final String SESSION_TOKEN = "session/token+EXAMPLE";

    private static Path state;
    private static Path wireLog;
    private static Process fake;
    private static int port;

    private Atom atom;

    @BeforeAll
    static void startFake() throws Exception {
        Path module = Path.of(System.getProperty("atom.module", System.getProperty("user.dir")));
        Path script = module.resolve("tools/fake_lambda.py");
        assumeTrue(Files.isRegularFile(script), "tools/fake_lambda.py is not there");
        assumeTrue(commandExists("python3"), "python3 is not on the PATH");
        state = Files.createTempDirectory("fake-lambda-state");
        wireLog = state.resolve("wire.log");
        Files.writeString(wireLog, "");
        scenario("{\"status\": 200, \"body\": \"{}\"}");
        port = freePort();
        fake = new ProcessBuilder("python3", script.toString(), String.valueOf(port), state.toString(),
                wireLog.toString()).redirectErrorStream(true).start();
        waitForPort(port);
    }

    @AfterAll
    static void stopFake() {
        if (fake != null) {
            fake.destroy();
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        atom = Atom.of();
        Files.writeString(wireLog, "");
    }

    // ---------------------------------------------------------------- the fake service

    private static void scenario(String json) throws IOException {
        Files.writeString(state.resolve("respond.json"), json);
    }

    private static void waitForPort(int port) throws Exception {
        for (int attempt = 0; attempt < 100; attempt++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 200);
                return;
            } catch (IOException notYet) {
                Thread.sleep(50);
            }
        }
        throw new IllegalStateException("the fake Lambda never started on " + port);
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static boolean commandExists(String name) {
        String path = System.getenv("PATH");
        if (path == null) {
            return false;
        }
        for (String entry : path.split(java.io.File.pathSeparator)) {
            if (!entry.isBlank() && Files.isExecutable(Path.of(entry).resolve(name))) {
                return true;
            }
        }
        return false;
    }

    private static List<Map<String, Object>> wire() {
        List<Map<String, Object>> records = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(wireLog, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    records.add(Json.parseObject(line));
                }
            }
        } catch (IOException ignored) {
            // no request was recorded
        }
        return records;
    }

    // ---------------------------------------------------------------- the runner's contract

    private Atom endpoint() {
        return atom.input("endpoint", "http://127.0.0.1:" + port);
    }

    /** The atom as the runner starts it, with credentials in the credential store. */
    private Atom function(String name) {
        return endpoint().input("function", name).input("region", "us-east-1")
                .file(".secrets.json", Json.write(Map.of("accessKey", ACCESS_KEY, "secretKey", SECRET_KEY)));
    }

    private static void refused(AtomResult run, String code) {
        run.assertRefused();
        assertEquals("error", run.status(), run.console());
        assertEquals(code, run.field("errorCode"), run.console() + "\n" + run.field("message"));
    }

    // ---------------------------------------------------------------- the checks

    @Test
    @DisplayName("a JSON answer comes back byte for byte, and the request is the one the Invoke API expects")
    void invokesAndReadsTheAnswer() throws Exception {
        scenario("{\"status\": 200, \"body\": \"{\\\"ok\\\": true, \\\"count\\\": 3}\", "
                + "\"headers\": {\"x-amz-executed-version\": \"42\"}, "
                + "\"logResult\": \"START RequestId: 1\\nEND RequestId: 1\\n\"}");
        AtomResult run = function("my-function").input("payload", "{\"a\": 1}").run();

        run.assertOk();
        assertEquals("{\"ok\": true, \"count\": 3}", run.field("payload"));
        assertEquals("json", run.field("payloadType"));
        assertEquals("200", run.field("statusCode"));
        assertEquals("42", run.field("executedVersion"));
        assertEquals("", run.field("functionError"));
        assertEquals("START RequestId: 1\nEND RequestId: 1\n", run.field("logTail"));

        List<Map<String, Object>> records = wire();
        assertEquals(1, records.size(), "one request, no retry");
        Map<String, Object> record = records.get(0);
        assertEquals(true, record.get("signatureOk"), String.valueOf(record.get("signatureProblem")));
        assertEquals("/2015-03-31/functions/my-function/invocations", record.get("path"));
        Map<?, ?> headers = (Map<?, ?>) record.get("headers");
        assertEquals("Tail", headers.get("x-amz-log-type"));
        assertEquals("application/json", headers.get("content-type"));
        assertEquals("{\"a\": 1}", record.get("body"));
    }

    @Test
    @DisplayName("the payload is the caller's bytes: multi-byte characters and content-length are exact")
    void sendsTheExactPayloadBytes() throws Exception {
        String answer = "{\"text\": \"第一行\\n第二行 \\\"quoted\\\"\", \"size\": 2}";
        scenario("{\"body\": " + Json.write(answer) + "}");
        String payload = "{\"say\": \"你好\"}";
        AtomResult run = function("echo").input("payload", payload).run();

        run.assertOk();
        assertEquals(answer, run.field("payload"));
        Map<String, Object> record = wire().get(0);
        assertEquals(payload, record.get("body"));
        assertEquals(String.valueOf(payload.getBytes(StandardCharsets.UTF_8).length),
                String.valueOf(((Map<?, ?>) record.get("headers")).get("content-length")));
    }

    @Test
    @DisplayName("leading and trailing whitespace in the payload is part of the bytes that get signed")
    void keepsPayloadWhitespace() throws Exception {
        String payload = "  {\"padded\": true}\n";
        scenario("{\"body\": \"{\\\"ok\\\": true}\"}");
        AtomResult run = function("echo").input("payload", payload).run();

        run.assertOk();
        assertEquals(payload, wire().get(0).get("body"));
    }

    @Test
    @DisplayName("a text answer is refused unless returnValueAsString is set, and then it is recognised as text")
    void handlesTextAnswers() throws Exception {
        scenario("{\"body\": \"plain text, not JSON\"}");
        AtomResult refused = function("echo").input("payload", "{}").run();
        refused(refused, "40008");
        assertTrue(refused.field("message").contains("returnValueAsString"), refused.field("message"));

        AtomResult text = function("echo").input("payload", "{}").input("returnValueAsString", "true").run();
        text.assertOk();
        assertEquals("plain text, not JSON", text.field("payload"));
        assertEquals("text", text.field("payloadType"));

        scenario("{\"body\": \"{\\\"looks\\\": \\\"structured\\\"}\"}");
        AtomResult json = function("echo").input("payload", "{}").input("returnValueAsString", "true").run();
        json.assertOk();
        assertEquals("json", json.field("payloadType"), "a JSON answer stays JSON even when text was requested");
    }

    @Test
    @DisplayName("a function error is named by function, type and message")
    void reportsAFunctionError() throws Exception {
        scenario("{\"status\": 200, \"body\": \"{\\\"errorMessage\\\": \\\"boom\\\", \\\"errorType\\\": "
                + "\\\"RuntimeError\\\"}\", \"headers\": {\"x-amz-function-error\": \"Unhandled\"}}");
        AtomResult run = function("broken").input("payload", "{}").run();

        refused(run, "40007");
        String message = run.field("message");
        assertTrue(message.contains("broken") && message.contains("Unhandled") && message.contains("boom"), message);
    }

    @Test
    @DisplayName("a 404 is 'no such function', a 503 is a third-party failure")
    void mapsServiceAnswers() throws Exception {
        scenario("{\"status\": 404, \"body\": \"{\\\"message\\\": \\\"Function not found: arn:aws:lambda:us-east-1:1:"
                + "function:nope\\\", \\\"__type\\\": \\\"ResourceNotFoundException\\\"}\"}");
        AtomResult notFound = function("nope").run();
        refused(notFound, "40006");
        assertTrue(notFound.field("message").contains("no such function"), notFound.field("message"));

        scenario("{\"status\": 503, \"body\": \"{\\\"message\\\": \\\"Service Unavailable\\\"}\"}");
        AtomResult server = function("my-function").run();
        refused(server, "50201");
    }

    @Test
    @DisplayName("a wrong secret is a 403 the fake really refuses, and the atom says so")
    void reportsABadSignature() throws Exception {
        scenario("{\"body\": \"{\\\"ok\\\": true}\"}");
        AtomResult run = endpoint().input("function", "my-function").input("region", "us-east-1")
                .file(".secrets.json", Json.write(Map.of("accessKey", ACCESS_KEY, "secretKey", "not-the-secret")))
                .run();

        refused(run, "40005");
        String message = run.field("message").toLowerCase();
        assertTrue(message.contains("signature") || message.contains("403"), message);
        assertEquals(false, wire().get(0).get("signatureOk"), "the fake must have refused the signature");
    }

    @Test
    @DisplayName("a body shorter than its declared length is unreadable JSON, not a silent pass")
    void refusesATruncatedBody() throws Exception {
        scenario("{\"body\": \"{\\\"complete\\\": true}\", \"contentLength\": 6}");
        AtomResult run = function("my-function").run();

        refused(run, "40008");
        assertTrue(run.field("message").contains("not JSON"), run.field("message"));
    }

    @Test
    @DisplayName("an ARN is used verbatim in the path, and a name with spaces and slashes is percent-encoded")
    void encodesTheFunctionName() throws Exception {
        String arn = "arn:aws:lambda:us-east-1:123456789012:function:my-function";
        scenario("{\"body\": \"{\\\"ok\\\": true}\"}");
        AtomResult byArn = function(arn).run();
        byArn.assertOk();
        Map<String, Object> record = wire().get(0);
        assertEquals(arn, record.get("function"));
        assertEquals("/2015-03-31/functions/" + arn + "/invocations", record.get("path"));
        assertEquals(true, record.get("signatureOk"), String.valueOf(record.get("signatureProblem")));

        Files.writeString(wireLog, "");
        String name = "weird name/with#bits";
        AtomResult byName = function(name).run();
        byName.assertOk();
        String path = String.valueOf(wire().get(0).get("path"));
        assertEquals(name, wire().get(0).get("function"));
        assertTrue(path.contains("%20") && path.contains("%2F") && path.contains("%23"), path);
        assertFalse(path.contains(" "), path);
    }

    @Test
    @DisplayName("no payload means no body and no content-type header")
    void sendsNoBodyWithoutAPayload() throws Exception {
        scenario("{\"body\": \"{\\\"ok\\\": true}\"}");
        AtomResult run = function("my-function").run();

        run.assertOk();
        Map<String, Object> record = wire().get(0);
        assertEquals(0, ((Number) record.get("bodyBytes")).intValue());
        assertFalse(((Map<?, ?>) record.get("headers")).containsKey("content-type"), "no body, no content type");
        assertEquals(true, record.get("signatureOk"), String.valueOf(record.get("signatureProblem")));
    }

    @Test
    @DisplayName("a payload that is not JSON is refused before anything is sent")
    void refusesAMalformedPayload() throws Exception {
        scenario("{\"body\": \"{\\\"ok\\\": true}\"}");
        AtomResult run = function("my-function").input("payload", "{not json").run();

        refused(run, "40003");
        assertTrue(wire().isEmpty(), "a request was sent for a payload that is not JSON");
    }

    @Test
    @DisplayName("function, region and credentials are required before a request is made")
    void refusesIncompleteInput() throws Exception {
        scenario("{\"body\": \"{\\\"ok\\\": true}\"}");

        AtomResult noFunction = Atom.of().input("endpoint", "http://127.0.0.1:" + port).input("region", "us-east-1")
                .file(".secrets.json", Json.write(Map.of("accessKey", ACCESS_KEY, "secretKey", SECRET_KEY))).run();
        refused(noFunction, "40001");

        AtomResult noRegion = Atom.of().input("endpoint", "http://127.0.0.1:" + port).input("function", "my-function")
                .file(".secrets.json", Json.write(Map.of("accessKey", ACCESS_KEY, "secretKey", SECRET_KEY))).run();
        refused(noRegion, "40002");

        AtomResult noCredentials = Atom.of().input("endpoint", "http://127.0.0.1:" + port)
                .input("function", "my-function").input("region", "us-east-1").run();
        refused(noCredentials, "40004");
        assertTrue(wire().isEmpty(), "nothing may be sent without the inputs the atom needs");
    }

    @Test
    @DisplayName("the region can come from the build environment, and it is signed into the credential scope")
    void takesTheRegionFromTheEnvironment() throws Exception {
        scenario("{\"body\": \"{\\\"ok\\\": true}\", \"expectRegion\": \"eu-west-1\"}");
        AtomResult run = endpoint().input("function", "my-function").env("AWS_REGION", "eu-west-1")
                .file(".secrets.json", Json.write(Map.of("accessKey", ACCESS_KEY, "secretKey", SECRET_KEY))).run();

        run.assertOk();
        assertEquals("eu-west-1", run.field("region"));
        Map<?, ?> headers = (Map<?, ?>) wire().get(0).get("headers");
        assertTrue(String.valueOf(headers.get("authorization")).contains("eu-west-1"),
                String.valueOf(headers.get("authorization")));
    }

    @Test
    @DisplayName("a session token travels in its own header and is signed")
    void sendsTheSessionToken() throws Exception {
        scenario("{\"body\": \"{\\\"ok\\\": true}\"}");
        AtomResult run = endpoint().input("function", "my-function").input("region", "us-east-1")
                .file(".secrets.json", Json.write(Map.of("accessKey", ACCESS_KEY, "secretKey", SECRET_KEY,
                        "sessionToken", SESSION_TOKEN)))
                .run();

        run.assertOk();
        Map<String, Object> record = wire().get(0);
        Map<?, ?> headers = (Map<?, ?>) record.get("headers");
        assertEquals(SESSION_TOKEN, headers.get("x-amz-security-token"));
        assertTrue(String.valueOf(headers.get("authorization")).contains("x-amz-security-token"));
        assertEquals(true, record.get("signatureOk"), String.valueOf(record.get("signatureProblem")));
    }

    @Test
    @DisplayName("a log tail that is not base64 is dropped, not turned into an error")
    void ignoresABadLogTail() throws Exception {
        scenario("{\"body\": \"{\\\"ok\\\": true}\", \"headers\": {\"X-Amz-Log-Result\": \"!!!not base64!!!\"}}");
        AtomResult run = function("my-function").run();

        run.assertOk();
        assertEquals("", run.field("logTail"));
    }

    @Test
    @DisplayName("300 KB goes out whole and comes back whole")
    void handlesABigPayload() throws Exception {
        String answer = Json.write(Map.of("blob", "x".repeat(300000)));
        String request = Json.write(Map.of("blob", "y".repeat(300000)));
        scenario("{\"body\": " + Json.write(answer) + "}");
        AtomResult run = function("big").input("payload", request).run();

        run.assertOk();
        assertEquals(answer, run.field("payload"), "the response was cut");
        Map<String, Object> record = wire().get(0);
        assertEquals(request, record.get("body"), "the request was cut");
        assertEquals(true, record.get("signatureOk"), String.valueOf(record.get("signatureProblem")));
    }

    @Test
    @DisplayName("the request id is passed through, and the secret never reaches the outputs")
    void passesTheRequestIdAndKeepsTheSecret() throws Exception {
        scenario("{\"body\": \"{\\\"ok\\\": true}\", \"requestId\": \"1234abcd-0000-4000-8000-000000000001\"}");
        AtomResult run = function("my-function").run();

        run.assertOk();
        assertEquals("1234abcd-0000-4000-8000-000000000001", run.field("requestId"));
        assertFalse(run.exists(".secrets.json"), ".secrets.json was left behind");
        assertFalse(run.file("output.json").contains(SECRET_KEY), "the secret leaked into the outputs");
    }

    @Test
    @DisplayName("the timeout is the atom's own: an 8 s function with a 5 s limit fails as 50203")
    void honoursTheTimeout() throws Exception {
        scenario("{\"body\": \"{\\\"ok\\\": true}\", \"delay\": 8}");
        long started = System.currentTimeMillis();
        AtomResult run = function("slow").input("timeoutSeconds", "5").run();
        long elapsed = (System.currentTimeMillis() - started) / 1000;

        refused(run, "50203");
        assertTrue(elapsed < 20, "the atom waited far past its timeout, took " + elapsed + "s");
    }
}
