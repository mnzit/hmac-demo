package com.mnzit.hmac.demo.util;

import com.mnzit.hmac.demo.dto.BaseClass;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
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
public class SignatureBuilder extends BaseClass {

    private static final String HMAC_SHA_512 = "HmacSHA512";
    private String algorithm = HMAC_SHA_512;
    private String apiSecret;
    private String body;
    private static final byte DELIMITER = '|';
    private String contentType;
    private String path;
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

    public SignatureBuilder path(String path) {
        this.path = path;
        return this;
    }

    public SignatureBuilder secret(String apiSecret) {
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

    public SignatureBuilder body(String body) {
        this.body = body;
        return this;
    }

    public SignatureBuilder contentType(String contentType) {
        this.contentType = contentType;
        return this;
    }

    /**
     * Signature: |method|path|contentType|username|nonce|timestamp|body|
     *
     * @return
     */
    public byte[] buildRequestSignature() {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(contentType, "contenttype");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(body, "body");

        log.debug("=========Signature Elements begin=========");
        log.debug("method : {}", method);
        log.debug("path : {}", path);
        log.debug("contentType : {}", contentType);
        log.debug("username : {}", username);
        log.debug("nonce : {}", nonce);
        log.debug("timestamp : {}", timestamp);
        log.debug("body : {}", body);
        log.debug("secretKey : {}", apiSecret);
        log.debug("=========Signature Elements end===========");

        try {
            final Mac digest = Mac.getInstance(algorithm);
            SecretKeySpec secretKey = new SecretKeySpec(apiSecret.getBytes(StandardCharsets.UTF_8), algorithm);
            digest.init(secretKey);

            digest.update(DELIMITER);
            digest.update(method.getBytes(StandardCharsets.UTF_8));

            digest.update(path.getBytes(StandardCharsets.UTF_8));
            digest.update(DELIMITER);

            digest.update(DELIMITER);
            digest.update(contentType.getBytes(StandardCharsets.UTF_8));

            digest.update(DELIMITER);
            digest.update(username.getBytes(StandardCharsets.UTF_8));

            digest.update(DELIMITER);
            digest.update(nonce.getBytes(StandardCharsets.UTF_8));

            digest.update(DELIMITER);
            digest.update(timestamp.getBytes(StandardCharsets.UTF_8));

            digest.update(DELIMITER);
            digest.update(
                    SHA256Util.getSHA256Hash(
                            body.getBytes(StandardCharsets.UTF_8))
                            .getBytes(StandardCharsets.UTF_8));

            digest.update(DELIMITER);

            final byte[] signatureBytes = digest.doFinal();
            digest.reset();

            return EncodingUtil.toHexString(signatureBytes).getBytes(StandardCharsets.UTF_8);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Can't create signature: {}, {}" + e.getMessage(), e);
        } catch (InvalidKeyException ex) {
            log.error("Invalid Key Exception : {}, {}", ex.getMessage());
        } catch (Exception ex) {
            log.error("Exception: {}, {}", ex.getMessage());
        }

        return null;
    }
    
     /**
     * Signature: |nonce|timestamp|body|
     *
     * @return
     */
    public byte[] buildResponseSignature() {
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(body, "body");

        log.debug("=========Signature Elements begin=========");
        log.debug("nonce : {}", nonce);
        log.debug("timestamp : {}", timestamp);
        log.debug("body : {}", body);
        log.debug("secretKey : {}", apiSecret);
        log.debug("=========Signature Elements end===========");

        try {
            final Mac digest = Mac.getInstance(algorithm);
            SecretKeySpec secretKey = new SecretKeySpec(apiSecret.getBytes(StandardCharsets.UTF_8), algorithm);
            digest.init(secretKey);

            digest.update(DELIMITER);
            digest.update(nonce.getBytes(StandardCharsets.UTF_8));

            digest.update(DELIMITER);
            digest.update(timestamp.getBytes(StandardCharsets.UTF_8));

            digest.update(DELIMITER);
            digest.update(
                    SHA256Util.getSHA256Hash(
                            body.getBytes(StandardCharsets.UTF_8))
                            .getBytes(StandardCharsets.UTF_8));

            digest.update(DELIMITER);

            final byte[] signatureBytes = digest.doFinal();
            digest.reset();

            return EncodingUtil.toHexString(signatureBytes).getBytes(StandardCharsets.UTF_8);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Can't create signature: {}, {}" + e.getMessage(), e);
        } catch (InvalidKeyException ex) {
            log.error("Invalid Key Exception : {}, {}", ex.getMessage());
        } catch (Exception ex) {
            log.error("Exception: {}, {}", ex.getMessage());
        }

        return null;
    }

    public String buildSignatureBase64Encoded() {
        return EncodingUtil.toBase64String(buildRequestSignature());
    }

    public String buildSignatureHexEncoded() {
        return EncodingUtil.toHexString(buildRequestSignature());
    }

    public boolean isHashEquals(String expectedSignature) {
        return buildSignatureBase64Encoded().equals(expectedSignature);
    }
}
