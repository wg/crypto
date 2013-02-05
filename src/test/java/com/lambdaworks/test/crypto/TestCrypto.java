// Copyright (C) 2012 - Will Glozer.  All rights reserved.

package com.lambdaworks.test.crypto;

import com.lambdaworks.crypto.Cipher;
import com.lambdaworks.crypto.Crypto;
import org.junit.Test;
import org.junit.internal.AssumptionViolatedException;

import static org.junit.Assert.*;
import static com.lambdaworks.crypto.Crypto.*;
import static com.lambdaworks.crypto.Cipher.Algorithm.*;
import static com.lambdaworks.crypto.Cipher.Mode.*;

public class TestCrypto {
    @Test
    public void cpu_flags() {
        assertTrue(Crypto.AESNI);
        assertTrue(Crypto.PCLMUL);
    }

    @Test(expected = IllegalArgumentException.class)
    public void invalid_aes_key_length() {
        Crypto.cipher(AES, CBC, new byte[12], null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void aes_cbc_null_iv() {
        Crypto.cipher(AES, CBC, new byte[16], null);
    }

    @Test
    public void close_cipher() {
        Cipher cipher = Crypto.cipher(AES, CBC, new byte[16], new byte[16]);
        cipher.close();
    }

    @Test(expected = NullPointerException.class)
    public void compare_null_array_A() {
        compare(null, array(0), 1);
    }

    @Test(expected = NullPointerException.class)
    public void compare_null_array_B() {
        compare(array(0), null, 1);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void compare_array_too_short0() {
        assertFalse(compare(array(0), array(0),    2));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void compare_array_too_short1() {
        assertFalse(compare(array(0), array(0, 1), 2));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
        public void compare_array_too_short2() {
        assertFalse(compare(array(0, 1), array(0), 2));
    }

    @Test
    public void compare_valid() {
        assertTrue(compare(array(0), array(0), 1));
        assertFalse(compare(array(0), array(1), 1));
        assertTrue(compare(array(0, 1, 2), array(0, 1, 3), 2));
        assertFalse(compare(array(0, 1, 2), array(0, 1, 3), 3));
    }

    @Test
    public void uniform_valid() {
        if (!RDRAND) throw new AssumptionViolatedException("RDRAND supported");
        long n = uniform(10);
        assertTrue(n >= 0 && n < 10);
    }

    @Test(expected = NullPointerException.class)
    public void bytes_null_array() {
        if (!RDRAND) throw new AssumptionViolatedException("RDRAND supported");
        bytes(null, 1);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void bytes_array_too_short() {
        if (!RDRAND) throw new AssumptionViolatedException("RDRAND supported");
        bytes(new byte[1], 2);
    }

    @Test
    public void bytes_valid() {
        if (!RDRAND) throw new AssumptionViolatedException("RDRAND supported");
        byte[] bytes = new byte[10];
        bytes(bytes, bytes.length);
    }

    private byte[] array(int... n) {
        byte[] bytes = new byte[n.length];
        for (int i = 0; i < n.length; i++) {
            bytes[i] = (byte) n[i];
        }
        return bytes;
    }
}
