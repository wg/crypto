// Copyright (C) 2012 - Will Glozer.  All rights reserved.

package com.lambdaworks.crypto;

/**
 * A symmetric cipher in a specific mode of operation. A {@link Cipher}
 * instance may be used to {@link #encrypt encrypt} and {@link #decrypt decrypt}
 * data and provides optional {@link #authenticate authentication} of
 * ciphertext and any additional authenticated data.
 *
 * @author  Will Glozer
 */
public abstract class Cipher {
    public static enum Algorithm { AES }
    public static enum Mode { CBC, CTR, GCM }
    public static enum Mac { SHA2, SHA3 }

    /**
     * Transform cipher into an authenticated cipher using the specified
     * message authentication algorithm.
     *
     * @param   mac     Authentication algorithm.
     * @param   bits    Size of MAC in bits.
     * @param   key     Authentication key.
     */
    public void authenticate(Mac mac, int bits, byte[] key) {
        authenticate(state, mac.ordinal(), bits, key);
    }

    /**
     * Perform in-place encryption. Length must be a multiple of the cipher's
     * block size except for the final block in stream modes. No padding is
     * performed.
     *
     * @param   bytes   Data to encrypt.
     * @param   len     Length of data.
     */
    public void encrypt(byte[] bytes, int len) {
        encrypt(state, bytes, len);
    }

    /**
     * Perform in-place decryption. Length must be a multiple of the cipher's
     * block size except for the final block in stream modes. No padding removal
     * is performed.
     *
     * @param   bytes   Data to decrypt.
     * @param   len     Length of data.
     */
    public void decrypt(byte[] bytes, int len) {
        decrypt(state, bytes, len);
    }

    /**
     * Include additional authenticated data in the authenticated cipher's
     * output MAC.
     *
     * @param   bytes   Additional authenticated data.
     * @param   len     Length of data.
     */
    public void aad(byte[] bytes, int len) {
        aad(state, bytes, len);
    }

    /**
     * Generate a message authentication code for all encrypted data and
     * any associated data.
     *
     * @return  A message authentication code.
     *
     * @throws IllegalStateException when the cipher is not authenticated.
     */
    public byte[] mac() {
        return mac(state);
    }

    /**
     * Reset cipher in preparation for further encryption or decryption.
     * When using an authenticated cipher the {@link #authenticate authenticate}
     * method must also be called again.
     *
     * @param   iv  Initialization vector.
     */
    public void reset(byte[] iv) {
        reset(state, iv);
    }

    /**
     * Free all native resources.
     */
    public void close() {
        close(state);
    }

    protected Cipher(byte[] key, byte[] iv) {
        state = init(key, iv);
    }

    protected abstract long init(byte[] key, byte[] iv);

    protected abstract void encrypt(long state, byte[] bytes, int len);
    protected abstract void decrypt(long state, byte[] bytes, int len);

    protected native void authenticate(long state, int type, int bits, byte[] key);
    protected abstract void aad(long state, byte[] bytes, int len);
    protected abstract byte[] mac(long state);

    protected abstract void reset(long state, byte[] iv);
    protected native void close(long state);

    protected long state;

    static class CBC extends Cipher {
        CBC (byte[] key, byte[] iv) {
            super(key, iv);
        }

        protected native long init(byte[] key, byte[] iv);
        protected native void aad(long state, byte[] bytes, int len);
        protected native void encrypt(long state, byte[] bytes, int len);
        protected native void decrypt(long state, byte[] bytes, int len);
        protected native byte[] mac(long state);
        protected native void reset(long state, byte[] iv);
    }

    static class CTR extends Cipher {
        CTR (byte[] key, byte[] icb) {
            super(key, icb);
        }

        protected native long init(byte[] key, byte[] icb);
        protected native void aad(long state, byte[] bytes, int len);
        protected native void encrypt(long state, byte[] bytes, int len);
        protected native void decrypt(long state, byte[] bytes, int len);
        protected native byte[] mac(long state);
        protected native void reset(long state, byte[] iv);
    }

    static class GCM extends Cipher {
        GCM (byte[] key, byte[] iv) {
            super(key, iv);
        }

        protected native long init(byte[] key, byte[] iv);
        protected native void aad(long state, byte[] bytes, int len);
        protected native void encrypt(long state, byte[] bytes, int len);
        protected native void decrypt(long state, byte[] bytes, int len);
        protected native byte[] mac(long state);
        protected native void reset(long state, byte[] iv);
    }
}
