package com.mnzit.hmac.demo.util;

import java.security.MessageDigest;
import java.util.Base64;

/**
 * @author Manjit Shakya
 * @email manjit.shakya@f1soft.com
 */
public class SHA256Util {

    public static String getSHA256Hash(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] hash = md.digest(input);

        return Base64.getEncoder().encodeToString(hash);
    }
}
