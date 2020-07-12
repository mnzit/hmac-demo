package com.mnzit.hmac.demo.dto;

import java.io.Serializable;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

/**
 *
 * @author Manjit Shakya <mnzitshakya@gmail.com>
 */
public class BaseClass implements Serializable{

    public String toString() {
        return ReflectionToStringBuilder.toString(this);
    }
}
