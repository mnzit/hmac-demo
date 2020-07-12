package com.mnzit.hmac.demo.validator;

import java.util.regex.Pattern;

/**
 *
 * @author Manjit Shakya <mnzitshakya@gmail.com>
 */
public class HmacResponseValidator {
    
     private final Pattern AUTHORIZATION_PATTERN = Pattern.compile("^HMAC (\\S+):(\\S+)$");
    private final Pattern AUTHORIZATION_TIMESTAMP_PATTERN = Pattern.compile("^[0-9]$");

//    private HmacRequestDTO hmacRequestDTO;

}
