package com.mnzit.hmac.demo.request.dto;

import com.mnzit.hmac.demo.dto.BaseClass;
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
public class HmacResponseDTO extends BaseClass {

    private String authorizationHeader;
    private String authorizationTimeStamp;
    private String payload;
}
