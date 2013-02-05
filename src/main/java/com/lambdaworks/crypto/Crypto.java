// Copyright (C) 2012 - Will Glozer.  All rights reserved.

package com.lambdaworks.crypto;

import com.lambdaworks.jni.*;

import static com.lambdaworks.crypto.Cipher.*;

/**
 * {@link Crypto} provides a simple Java interface to native cryptographic
 * acceleration instructions available on recent x86-64 CPUs. Specifically
 * this package supports AES in CBC, CTR, and GCM modes, authenticated
 * encryption using HMAC-SHA2 or SHA3, and secure random byte generation
 * using the RDRAND instruction.
 *
 * @author  Will Glozer
 */
public class Crypto {
    /** Flag indicating whether CPU supports AES-NI */
    public static boolean AESNI  = false;
    /** Flag indicating whether CPU supports PCLMUL */
    public static boolean PCLMUL = false;
    /** Flag indicating whether CPU supports RDRAND */
    public static boolean RDRAND = false;

    static {
        LibraryLoader loader = LibraryLoaders.loader();
        loader.load("crypto", true);
    }

    /**
     * Create a new symmetric cipher instance.
     *
     * @param   _    {@link Cipher.Algorithm#AES AES}.
     * @param   mode Cipher mode of operation.
     * @param   key  Key.
     * @param   iv   Initialization vector.
     *
     * @return A new {@link Cipher} instance.
     *
     * @throws UnsupportedOperationException when CPU does not support AES-NI.
     */
    public static Cipher cipher(Algorithm _, Mode mode, byte[] key, byte[] iv) {
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("KEY");
        }

        if (iv == null) {
            throw new IllegalArgumentException("IV");
        }

        switch (mode) {
            case CBC: return new CBC(key, iv);
            case CTR: return new CTR(key, iv);                
            case GCM: return new GCM(key, iv);
            default: throw new IllegalArgumentException();
        }
    }

    /**
     * Fill supplied array with cryptographically-secure random bytes.
     *
     * @param   bytes   Array to fill.
     * @param   len     Number of bytes to fill.
     *
     * @throws UnsupportedOperationException when CPU does not support RDRAND.
     */
    public static native void bytes(byte[] bytes, int len);

    /**
     * Generate one cryptographically-secure random long uniformly
     * distributed between [0, N).
     *
     * @param   n   Upper bound.
     *
     * @return  A random <code>long</code>.
     *
     * @throws UnsupportedOperationException when CPU does not support RDRAND.
     */
    public static native long uniform(long n);

    /**
     * Compare the first <code>len</code> bytes of two arrays using
     * a constant-time algorithm that does not leak timing information.
     *
     * @param   a   First array to compare.
     * @param   b   Second array to compare.
     * @param   len Number of bytes to compare.
     *
     * @return  True if the first <code>len</code> bytes of both arrays are identical.
     */
    public static native boolean compare(byte[] a, byte[] b, int len);

    private Crypto() {}
}
