package com.mnzit.hmac.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 *
 * @author Manjit Shakya <mnzitshakya@gmail.com>
 */
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthorizationParameter {
    
    private String userApplicationId;
    private String nonce;
    private String signature;
    private String timeStamp;

}
