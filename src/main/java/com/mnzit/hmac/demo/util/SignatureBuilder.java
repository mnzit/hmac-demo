package com.mnzit.hmac.demo.util;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.management.openmbean.InvalidKeyException;
import lombok.extern.slf4j.Slf4j;

/**
 *
 * @author Manjit Shakya <mnzitshakya@gmail.com>
 */
@Slf4j
public class SignatureBuilder {

    private static final String HMAC_SHA_512 = "HmacSHA512";
    private String algorithm = HMAC_SHA_512;
    private byte[] apiSecret;
    private byte[] body;
    private static final byte DELIMITER = '|';
    private String contentType;
    private String resource;
    private String timestamp;
    private String nonce;
    private String username;
    private String method;

    public String getAlgorithm() {
        return HMAC_SHA_512;
    }

    public SignatureBuilder username(String username) {
        this.username = username;
        return this;
    }

    public SignatureBuilder resource(String resource) {
        this.resource = resource;
        return this;
    }

    public SignatureBuilder secret(byte[] apiSecret) {
        this.apiSecret = apiSecret;
        return this;
    }

    public SignatureBuilder timestamp(String timestamp) {
        this.timestamp = timestamp;
        return this;
    }

    public SignatureBuilder nonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    public SignatureBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public SignatureBuilder method(String method) {
        this.method = method;
        return this;
    }

    public SignatureBuilder body(byte[] body) {
        this.body = body;
        return this;
    }

    public SignatureBuilder contentType(String contentType) {
        this.contentType = contentType;
        return this;
    }

    /**
     * Signature: [method|contentType|username|nonce|timestamp|SHA256(body)]
     *
     * @return
     */
    public byte[] buildSignature() {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(timestamp, "timestamp");

        try {
            final Mac digest = Mac.getInstance(algorithm);
            SecretKeySpec secretKey = new SecretKeySpec(apiSecret, algorithm);
            digest.init(secretKey);
            digest.update(DELIMITER);
            digest.update(method.getBytes(StandardCharsets.UTF_8));
            digest.update(DELIMITER);
            if (contentType != null && !contentType.isEmpty()) {
                digest.update(DELIMITER);
                digest.update(contentType.getBytes(StandardCharsets.UTF_8));
            }
            digest.update(DELIMITER);
            digest.update(username.getBytes(StandardCharsets.UTF_8));
            digest.update(DELIMITER);
            digest.update(nonce.getBytes(StandardCharsets.UTF_8));
            digest.update(DELIMITER);
            digest.update(timestamp.getBytes(StandardCharsets.UTF_8));
            digest.update(DELIMITER);
            digest.update(resource.getBytes(StandardCharsets.UTF_8));
            digest.update(DELIMITER);
            digest.update(EncodingUtil.toBase64String(SHA256Util.getSHA256Hash(body)).getBytes(StandardCharsets.UTF_8));
            digest.update(DELIMITER);

            final byte[] signatureBytes = digest.doFinal();
            digest.reset();
            return signatureBytes;

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Can't create signature: " + e.getMessage(), e);
        } catch (InvalidKeyException ex) {
            log.error("Invalid Key Exception");
        } catch (Exception ex) {
            log.error("Exception: {}", ex.getMessage());
        }

        return null;
    }

    public String buildSignatureBase64Encoded() {
        return EncodingUtil.toBase64String(buildSignature());
    }

    public String buildSignatureHexEncoded() {
        return EncodingUtil.toHexString(buildSignature());
    }

    public boolean isHashEquals(byte[] expectedSignature) {
        String signature = EncodingUtil.toBase64String(buildSignature());
        log.debug("Signature generated from request : " + signature);
        log.debug("Expected signature : " + new String(expectedSignature));
        return signature.equals(new String(expectedSignature));
    }

    @Override
    public String toString() {
        return "SignatureBuilder{"
                + "algorithm='" + algorithm + '\''
                + ", apiSecret=" + Arrays.toString(apiSecret)
                + ", body=" + Arrays.toString(body)
                + ", contentType='" + contentType + '\''
                + ", timestamp='" + timestamp + '\''
                + ", nonce='" + nonce + '\''
                + ", username='" + username + '\''
                + ", method='" + method + '\''
                + '}';
    }

}
