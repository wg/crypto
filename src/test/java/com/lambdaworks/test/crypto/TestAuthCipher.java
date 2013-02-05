// Copyright (C) 2012 - Will Glozer.  All rights reserved.

package com.lambdaworks.test.crypto;

import com.lambdaworks.crypto.Cipher;
import com.lambdaworks.crypto.Crypto;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.*;
import static com.lambdaworks.crypto.Cipher.Algorithm.*;
import static com.lambdaworks.crypto.Cipher.Mode.*;
import static com.lambdaworks.crypto.Cipher.Mac.*;
import static org.junit.Assert.assertEquals;

public class TestAuthCipher extends AbstractCipherTest {
    SecureRandom sr = new SecureRandom();
    byte[] key  = new byte[16];
    byte[] iv   = new byte[16];
    byte[] data = new byte[32];

    @Before
    public void setup() {
        sr.nextBytes(key);
        sr.nextBytes(iv);
        sr.nextBytes(data);
    }

    @Test
    public void sha2_hmac() throws Exception {
        verify(CBC, SHA2, 256);
        verify(CBC, SHA2, 512);
        verify(CTR, SHA2, 256);
        verify(CTR, SHA2, 512);
    }

    @Test
    public void sha3_mac() throws Exception {
        verify(CBC, SHA3, 256);
        verify(CBC, SHA3, 512);
        verify(CTR, SHA3, 256);
        verify(CTR, SHA3, 512);
    }

    @Test
    public void authenticate_valid_aad() {
        byte[] aad = new byte[64];
        sr.nextBytes(aad);

        Cipher cipher = Crypto.cipher(AES, CBC, key, iv);
        cipher.authenticate(SHA2, 256, key);
        cipher.aad(aad, aad.length);
        cipher.encrypt(data, data.length);
        byte[] tag = cipher.mac();

        cipher.reset(iv);
        cipher.authenticate(SHA2, 256, key);
        cipher.aad(aad, aad.length);
        cipher.decrypt(data, data.length);
        assertArrayEquals(tag, cipher.mac());
    }

    @Test
    public void authenticate_invalid_aad() {
        byte[] aad = new byte[64];
        sr.nextBytes(aad);

        Cipher cipher = Crypto.cipher(AES, CBC, key, iv);
        cipher.authenticate(SHA2, 256, key);
        cipher.aad(aad, aad.length);
        cipher.encrypt(data, data.length);
        byte[] tag = cipher.mac();

        aad[0]++;
        cipher.reset(iv);
        cipher.authenticate(SHA2, 256, key);
        cipher.aad(aad, aad.length);
        cipher.decrypt(data, data.length);
        assertFalse(Arrays.equals(tag, cipher.mac()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void invalid_sha2_mac_length() {
        Cipher cipher = Crypto.cipher(AES, CBC, key, iv);
        cipher.authenticate(SHA2, 160, key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void invalid_sha3_mac_length() {
        Cipher cipher = Crypto.cipher(AES, CBC, key, iv);
        cipher.authenticate(SHA3, 160, key);
    }

    @Test(expected = IllegalStateException.class)
    public void mac_requires_authenticate() {
        Cipher cipher = Crypto.cipher(AES, CBC, key, iv);
        cipher.mac();
    }

    private void verify(Cipher.Mode mode, Cipher.Mac mac, int bits) throws Exception {
        Cipher cipher = Crypto.cipher(AES, mode, key, iv);
        cipher.authenticate(mac, bits, key);
        cipher.encrypt(data, data.length);
        byte[] tag = cipher.mac();

        assertEquals(bits / 8, tag.length);

        cipher.reset(iv);
        cipher.authenticate(mac, bits, key);
        cipher.decrypt(data, data.length);
        assertArrayEquals(tag, cipher.mac());
    }
}


