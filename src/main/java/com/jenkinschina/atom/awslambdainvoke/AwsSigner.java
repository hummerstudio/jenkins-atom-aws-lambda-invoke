package com.jenkinschina.atom.awslambdainvoke;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * AWS Signature Version 4, hand-written.
 *
 * <p>Written out rather than pulled from an SDK: the atom makes one signed POST, and the AWS SDK for that is a lot of
 * classloader surface for a build step. The signer is generic -- the caller says which headers are signed -- so the
 * same class (modulo the package name) is carried by the other AWS atoms. It has to be exactly right: a signature
 * that is 99% correct is a 403.
 */
final class AwsSigner {

    private static final DateTimeFormatter AMZ_DATE = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'", Locale.ROOT);
    private static final DateTimeFormatter DATE_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd", Locale.ROOT);

    private final String accessKey;
    private final String secretKey;
    private final String sessionToken;
    private final String region;
    private final String service;

    AwsSigner(String accessKey, String secretKey, String sessionToken, String region, String service) {
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.sessionToken = sessionToken == null ? "" : sessionToken;
        this.region = region;
        this.service = service;
    }

    /**
     * Signs one request.
     *
     * @param sign me the headers that must be part of the signature (host and x-amz-date are added here)
     * @return every header the request needs, including the Authorization line
     */
    Map<String, String> headers(String method, String path, String query, String payload, String host,
                                Map<String, String> sign) {
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String amzDate = now.format(AMZ_DATE);
        String dateStamp = now.format(DATE_STAMP);
        String payloadHash = hex(sha256(payload.getBytes(StandardCharsets.UTF_8)));

        // canonical headers are sorted by lowercase name and their values trimmed
        TreeMap<String, String> canonical = new TreeMap<>();
        sign.forEach((name, value) -> canonical.put(name.toLowerCase(Locale.ROOT), value));
        canonical.put("host", host);
        canonical.put("x-amz-date", amzDate);
        if (!sessionToken.isEmpty()) {
            canonical.put("x-amz-security-token", sessionToken);
        }

        StringBuilder canonicalHeaders = new StringBuilder();
        StringBuilder signedHeaders = new StringBuilder();
        canonical.forEach((name, value) -> {
            canonicalHeaders.append(name).append(':').append(value.trim()).append('\n');
            signedHeaders.append(signedHeaders.isEmpty() ? "" : ";").append(name);
        });

        String canonicalRequest = method + "\n"
                + (path.isEmpty() ? "/" : path) + "\n"
                + (query == null ? "" : query) + "\n"
                + canonicalHeaders + "\n"
                + signedHeaders + "\n"
                + payloadHash;
        String scope = dateStamp + "/" + region + "/" + service + "/aws4_request";
        String stringToSign = "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n"
                + hex(sha256(canonicalRequest.getBytes(StandardCharsets.UTF_8)));

        byte[] signingKey = hmac(("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8), dateStamp);
        signingKey = hmac(signingKey, region);
        signingKey = hmac(signingKey, service);
        signingKey = hmac(signingKey, "aws4_request");
        String signature = hex(hmac(signingKey, stringToSign));

        Map<String, String> headers = new TreeMap<>(sign);
        headers.put("Authorization", "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope
                + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature);
        headers.put("X-Amz-Date", amzDate);
        if (!sessionToken.isEmpty()) {
            headers.put("X-Amz-Security-Token", sessionToken);
        }
        return headers;
    }

    private static byte[] hmac(byte[] key, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            hex.append(String.format(Locale.ROOT, "%02x", value));
        }
        return hex.toString();
    }
}
