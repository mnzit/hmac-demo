package com.mnzit.hmac.demo;

import com.mnzit.hmac.demo.request.dto.HmacRequestDTO;
import com.mnzit.hmac.demo.validator.HmacRequestValidator;
import java.nio.charset.StandardCharsets;
import lombok.extern.slf4j.Slf4j;

/**
 *
 * @author Manjit Shakya <mnzitshakya@gmail.com>
 */
@Slf4j
public class HmacMain {

    public static void main(String[] args) {
        log.debug("=============Starting HMAC module=============");

        HmacRequestValidator hmacRequestValidator = new HmacRequestValidator(
                HmacRequestDTO
                        .builder()
                        .authorizationHeader("")
                        .authorizationTimeStamp("")
                        .contentType("")
                        .method("")
                        .payload("".getBytes(StandardCharsets.UTF_8))
                        .build(),
                "secretKey",
                360L);

        hmacRequestValidator.validate();
    }

}
