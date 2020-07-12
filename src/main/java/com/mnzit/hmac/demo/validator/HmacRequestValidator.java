package com.mnzit.hmac.demo.validator;

import com.mnzit.hmac.demo.dto.AuthorizationParameter;
import com.mnzit.hmac.demo.dto.ServerResponse;
import com.mnzit.hmac.demo.request.dto.HmacRequestDTO;
import com.mnzit.hmac.demo.util.SignatureBuilder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;

/**
 *
 * @author Manjit Shakya <mnzitshakya@gmail.com>
 */
@Slf4j
public class HmacRequestValidator {

    private final Pattern AUTHORIZATION_PATTERN = Pattern.compile("^HMAC (\\S+):(\\S+):(\\S+)$");
    private final Pattern AUTHORIZATION_TIMESTAMP_PATTERN = Pattern.compile("^[0-9]*$");
    private final Pattern NONCE_PATTERN = Pattern.compile("^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$", Pattern.CASE_INSENSITIVE);

    private HmacRequestDTO hmacRequestDTO;
    private String secretKey;
    private final Long tolerance;

    public HmacRequestValidator(HmacRequestDTO hmacRequestDTO, String secretKey, Long tolerance) {
        this.hmacRequestDTO = hmacRequestDTO;
        this.secretKey = secretKey;
        this.tolerance = tolerance;
    }

    public ServerResponse validate() {

        ServerResponse serverResponse = new ServerResponse();

        try {

            serverResponse = nullOrEmptyValidator(serverResponse);

            if (serverResponse.getSuccess()) {

                serverResponse = validateHeaderPattern(serverResponse);

                if (serverResponse.getSuccess()) {

                    serverResponse = compareTimestampWithinTolerance(Long.valueOf(hmacRequestDTO.getAuthorizationTimeStamp()), tolerance, serverResponse);

                    if (serverResponse.getSuccess()) {

                        serverResponse = validateSignature(serverResponse);
                    }

                }

            }
        } catch (Exception e) {
            log.error("Exception : {}:{}", e.getMessage(), e);
            serverResponse = ServerResponse.buildFailure(e.getMessage());
        }

        return serverResponse;

    }

    /**
     *
     * @param serverResponse
     * @return serverResponse with success as true
     * @throws RuntimeException if authentication header or authentication
     * timestamp is not found
     */
    private ServerResponse nullOrEmptyValidator(ServerResponse serverResponse) {
        if ((hmacRequestDTO.getAuthorizationHeader() != null && hmacRequestDTO.getAuthorizationHeader().trim().length() > 0) && (hmacRequestDTO.getAuthorizationTimeStamp() != null && hmacRequestDTO.getAuthorizationTimeStamp().trim().length() > 0)) {
            serverResponse = serverResponse.build(serverResponse, true);
        } else {
            throw new RuntimeException("Error: Authentication Header or Authentication Timestamp is not found.");
        }
        return serverResponse;
    }

    /**
     *
     * @param serverResponse
     * @return serverResponse with success as true and authorizationParameter
     * object if the authHeader and timestamp matches the required pattern's
     * @throws RuntimeException if pattern does not matches
     */
    private ServerResponse validateHeaderPattern(ServerResponse serverResponse) {
        Matcher matcher = AUTHORIZATION_PATTERN.matcher(hmacRequestDTO.getAuthorizationHeader());
        if (matcher.matches()) {

            AuthorizationParameter authorizationParameter = AuthorizationParameter
                    .builder()
                    .userApplicationId(matcher.group(1))
                    .nonce(matcher.group(2))
                    .signature(matcher.group(3))
                    .build();

            matcher = AUTHORIZATION_TIMESTAMP_PATTERN.matcher(hmacRequestDTO.getAuthorizationTimeStamp());

            if (matcher.matches()) {
                authorizationParameter.setTimeStamp(hmacRequestDTO.getAuthorizationTimeStamp());

                serverResponse.setObject(authorizationParameter);
            } else {
                throw new RuntimeException("Error: X-Authorization-Timestamp format is not correct.");
            }

            serverResponse = vaildateNonce(serverResponse, authorizationParameter.getNonce());

        } else {
            throw new RuntimeException("Error: X-Authorization format is not correct");
        }

        return serverResponse.build(serverResponse, true);
    }

    /**
     *
     * @param serverResponse
     * @param nonce
     * @return serverResponse as true if valid Nonce
     * @throws RuntimeException if nonce pattern doesnt matches or if length is
     * not correct
     */
    private ServerResponse vaildateNonce(ServerResponse serverResponse, String nonce) {
        Matcher matcher = NONCE_PATTERN.matcher(nonce);

        if (!matcher.matches()) {
            log.error("Nonce must be valid uuidv4");
            throw new RuntimeException("Error: X-Authorization <nonce> is not valid.");
        }

        return serverResponse.build(serverResponse, true);
    }

    /**
     * Check if timestamp is within tolerance
     *
     * @param unixTimestamp
     * @param tolerance
     * @param serverResponse
     * @return serverResponse with success true if timestamp is within tolerance
     * range
     * @throws RuntimeException if timestamp is from future or past
     */
    private ServerResponse compareTimestampWithinTolerance(long unixTimestamp, long tolerance, ServerResponse serverResponse) {
        long unixCurrent = System.currentTimeMillis() / 1000L;
        if (unixTimestamp > unixCurrent + tolerance) {

            throw new RuntimeException("Error: X-Authorization-Timestamp is too far in the future.");

        } else if (unixTimestamp < unixCurrent - tolerance) {

            throw new RuntimeException("Error: X-Authorization-Timestamp is too far in the past.");

        } else {

            return serverResponse.build(serverResponse, true);

        }
    }

    /**
     *
     * @param serverResponse
     * @return serverResponse with success true if signature matches
     * @throws RuntimeException if signature does not matches
     */
    private ServerResponse validateSignature(ServerResponse serverResponse) {
        AuthorizationParameter authorizationParameter = (AuthorizationParameter) serverResponse.getObject();

        SignatureBuilder signatureBuilder = new SignatureBuilder()
                .method(hmacRequestDTO.getMethod().toUpperCase())
                .path(hmacRequestDTO.getPath())
                .contentType(hmacRequestDTO.getContentType() != null ? hmacRequestDTO.getContentType().toLowerCase() : "")
                .username(authorizationParameter.getUserApplicationId())
                .nonce(authorizationParameter.getNonce())
                .timestamp(authorizationParameter.getTimeStamp())
                .body(hmacRequestDTO.getPayload() != null ? hmacRequestDTO.getPayload() : "")
                .secret(secretKey);

        if (!signatureBuilder.isHashEquals(authorizationParameter.getSignature())) {

            throw new RuntimeException("Error: Invalid authorization data.");
        }

        return serverResponse.build(serverResponse, true);
    }
}
