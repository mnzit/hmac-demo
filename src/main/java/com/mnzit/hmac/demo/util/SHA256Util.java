package com.mnzit.hmac.demo.util;

import java.security.MessageDigest;

/**
 * @author Manjit Shakya
 * @email manjit.shakya@f1soft.com
 */
public class SHA256Util {

    public static byte[] getSHA256Hash(byte[] input) throws Exception {
        // Static getInstance method is called with hashing SHA
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // digest() method called
        // to calculate message digest of an input
        // and return array of byte
        return md.digest(input);
    }
}
