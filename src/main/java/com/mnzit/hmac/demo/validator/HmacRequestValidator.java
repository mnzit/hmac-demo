package com.mnzit.hmac.demo.validator;

import com.mnzit.hmac.demo.dto.AuthorizationParameter;
import com.mnzit.hmac.demo.dto.ServerResponse;
import com.mnzit.hmac.demo.request.dto.HmacRequestDTO;
import com.mnzit.hmac.demo.util.SignatureBuilder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author Manjit Shakya <mnzitshakya@gmail.com>
 */
public class HmacRequestValidator {

    private final Pattern AUTHORIZATION_PATTERN = Pattern.compile("^HMAC (\\S+):(\\S+):([\\S]+)$");
    private final Pattern AUTHORIZATION_TIMESTAMP_PATTERN = Pattern.compile("^[0-9]$");

    private HmacRequestDTO hmacRequestDTO;
    private String secretKey;
    private final Long tolerance;

    public HmacRequestValidator(HmacRequestDTO hmacRequestDTO, String secretKey, Long tolerance) {
        this.hmacRequestDTO = hmacRequestDTO;
        this.secretKey = secretKey;
        this.tolerance = tolerance;
    }

    public ServerResponse validate() {

        ServerResponse serverResponse = ServerResponse.buildFailure();

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

        return serverResponse;

    }

    private ServerResponse nullOrEmptyValidator(ServerResponse serverResponse) {
        if ((hmacRequestDTO.getAuthorizationHeader() != null && hmacRequestDTO.getAuthorizationHeader().trim().length() > 0) && (hmacRequestDTO.getAuthorizationTimeStamp() != null && hmacRequestDTO.getAuthorizationTimeStamp().trim().length() > 0)) {
            serverResponse = serverResponse.build(serverResponse, true);
        }
        throw new RuntimeException("Authentication Header or Authentication is not found.");
    }

    private ServerResponse validateHeaderPattern(ServerResponse serverResponse) {
        Matcher matcher = AUTHORIZATION_PATTERN.matcher(hmacRequestDTO.getAuthorizationHeader());
        if (!matcher.matches()) {

            AuthorizationParameter authorizationParameter = AuthorizationParameter
                    .builder()
                    .userApplicationId(matcher.group(1))
                    .nonce(matcher.group(2))
                    .signature(matcher.group(3))
                    .build();

            matcher = AUTHORIZATION_TIMESTAMP_PATTERN.matcher(hmacRequestDTO.getAuthorizationTimeStamp());

            if (!matcher.matches()) {
                authorizationParameter.setTimeStamp(hmacRequestDTO.getAuthorizationTimeStamp());

                serverResponse.setObject(authorizationParameter);
            } else {
                throw new RuntimeException("Error: X-Authorization-Timestamp format is not correct");
            }

        } else {
            throw new RuntimeException("Error: X-Authorization format is not correct");
        }

        return serverResponse.build(serverResponse, true);
    }

    /**
     * Check if timestamp is within tolerance (360 seconds [6 minutes])
     *
     * @param unixTimestamp
     * @return non-zero if timestamp is outside tolerance (positive if in the
     * future; negative in the past); otherwise return zero
     */
    private ServerResponse compareTimestampWithinTolerance(long unixTimestamp, long tolerance, ServerResponse serverResponse) {
        long unixCurrent = System.currentTimeMillis() / 1000L;
        if (unixTimestamp > unixCurrent + tolerance) {

            new RuntimeException("Error: X-Authorization-Timestamp is too far in the future.");

        } else if (unixTimestamp < unixCurrent - tolerance) {

            new RuntimeException("Error: X-Authorization-Timestamp is too far in the past.");

        } else {

            return serverResponse.build(serverResponse, true);

        }
        return serverResponse.build(serverResponse, false);
    }

    private ServerResponse validateSignature(ServerResponse serverResponse) {
        AuthorizationParameter authorizationParameter = (AuthorizationParameter) serverResponse.getObject();

        SignatureBuilder signatureBuilder = new SignatureBuilder()
                .body(hmacRequestDTO.getPayload() != null ? hmacRequestDTO.getPayload() : "".getBytes())
                .method(hmacRequestDTO.getMethod().toUpperCase())
                .contentType(hmacRequestDTO.getContentType() != null ? hmacRequestDTO.getContentType().toLowerCase() : null)
                .username(authorizationParameter.getUserApplicationId())
                .nonce(authorizationParameter.getNonce())
                .timestamp(authorizationParameter.getTimeStamp())
                .secret(secretKey.getBytes(StandardCharsets.UTF_8));

        if (!signatureBuilder.isHashEquals(authorizationParameter.getSignature().getBytes())) {

            new RuntimeException("Invalid authorization data.");
        }

        return serverResponse;
    }
}
