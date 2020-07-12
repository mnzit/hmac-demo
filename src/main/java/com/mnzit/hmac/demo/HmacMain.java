package com.mnzit.hmac.demo;

import com.mnzit.hmac.demo.dto.ServerResponse;
import com.mnzit.hmac.demo.request.dto.HmacRequestDTO;
import com.mnzit.hmac.demo.validator.HmacRequestValidator;
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
                        .authorizationHeader("HMAC Manjit:def1722b-fb12-478c-88e7-c1ec0c3938b0:NjNCN0Y1QzU4RjBGNkFCREUwNDY3QTI1NDVDMzhCMkQwOUMwQUE1QjE3QzlBRjAwN0M5OUU5Mzg4NDJFNzlEREVEQUNBMTg2MENFMzY3QzZFQ0EyNjM5OTc3NzEzMzhDN0QzNzdDQzY0RkEyRDhBRUE1NTg1NUNDRUE0MTczNDQ=")
                        .authorizationTimeStamp("1594524917")
                        .contentType("application/json")
                        .method("POST")
                        .path("/login?name=manjit&age=10")
                        .payload("Manjit")
                        .build(),
                "theSecret",
                900L);
        
        ServerResponse response = hmacRequestValidator.validate();
        
        log.debug("Response : {}", response);
    }
    
}
