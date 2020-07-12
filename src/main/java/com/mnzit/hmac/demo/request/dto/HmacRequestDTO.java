package com.mnzit.hmac.demo.request.dto;

import java.io.Serializable;
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
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class HmacRequestDTO implements Serializable {

    private String authorizationHeader;
    private String authorizationTimeStamp;
    private String contentType;
    private String method;
    private String path;
    private String payload;
}
