package com.mnzit.hmac.demo.util;

import java.security.SecureRandom;

/**
 * @author Manjit Shakya
 * @email manjit.shakya@f1soft.com
 */
public class RandomUtil {
    // A cryptographically secure random number generator.
    public static final SecureRandom secureRandom = new SecureRandom();

    // Generate a random byte array for cryptographic use.
    public static byte[] generateRandomBytes(final int size) {
        final byte[] key = new byte[size];
        secureRandom.nextBytes(key);
        return key;
    }
}
