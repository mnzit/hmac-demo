package com.mnzit.hmac.demo.util;

import java.util.Base64;
import java.util.Formatter;

/**
 * @author Manjit Shakya
 * @email manjit.shakya@f1soft.com
 */
public class EncodingUtil {

    public static String toHexString(byte[] bytes) {
        try (Formatter formatter = new Formatter()) {
            for (byte b : bytes) {
                formatter.format("%02x", b);
            }
            return formatter.toString().toUpperCase();
        } catch (Exception e) {
            throw e;
        }
    }

    public static String toBase64String(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
