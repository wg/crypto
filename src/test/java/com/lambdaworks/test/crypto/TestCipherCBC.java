// Copyright (C) 2012 - Will Glozer.  All rights reserved.

package com.lambdaworks.test.crypto;

import com.lambdaworks.crypto.Cipher;
import com.lambdaworks.crypto.Crypto;
import org.junit.Test;

import static org.junit.Assert.*;
import static com.lambdaworks.crypto.Cipher.Algorithm.*;
import static com.lambdaworks.crypto.Cipher.Mode.*;

public class TestCipherCBC extends AbstractCipherTest {
    /**
     * NIST SP800-30A test vectors.
     *
     * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
     */
    @Test
    public void nist_sp800_38a() throws Exception {
        byte[] key, iv, ptext, ctext;
        Cipher cipher;

        // F.2.1 CBC-AES128.Encrypt
        key    = hex("2b7e151628aed2a6abf7158809cf4f3c");
        iv     = hex("000102030405060708090a0b0c0d0e0f");
        cipher = Crypto.cipher(AES, CBC, key, iv);

        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("7649abac8119b246cee98e9b12e9197d");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("5086cb9b507219ee95db113a917678b2");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("73bed6b8e3c1743b7116e69e22229516");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("3ff1caa1681fac09120eca307586e1a7");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        cipher = Crypto.cipher(AES, CBC, key, iv);

        // F.2.2 CBC-AES128.Decrypt
        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("7649abac8119b246cee98e9b12e9197d");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("5086cb9b507219ee95db113a917678b2");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("73bed6b8e3c1743b7116e69e22229516");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("3ff1caa1681fac09120eca307586e1a7");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // F.2.3 CBC-AES192.Encrypt
        key    = hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        iv     = hex("000102030405060708090a0b0c0d0e0f");
        cipher = Crypto.cipher(AES, CBC, key, iv);

        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("4f021db243bc633d7178183a9fa071e8");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("b4d9ada9ad7dedf4e5e738763f69145a");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("571b242012fb7ae07fa9baac3df102e0");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("08b0e27988598881d920a9e64f5615cd");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        cipher = Crypto.cipher(AES, CBC, key, iv);

        // F.2.4 CBC-AES192.Decrypt
        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("4f021db243bc633d7178183a9fa071e8");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("b4d9ada9ad7dedf4e5e738763f69145a");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("571b242012fb7ae07fa9baac3df102e0");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("08b0e27988598881d920a9e64f5615cd");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // F.2.5 CBC-AES256.Encrypt
        key    = hex("603deb1015ca71be2b73aef0857d7781" +
                     "1f352c073b6108d72d9810a30914dff4");
        iv     = hex("000102030405060708090a0b0c0d0e0f");
        cipher = Crypto.cipher(AES, CBC, key, iv);

        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("9cfc4e967edb808d679f777bc6702c7d");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("39f23369a9d9bacfa530e26304231461");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("b2eb05e2c39be9fcda6c19078c6a9d1b");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        cipher = Crypto.cipher(AES, CBC, key, iv);

        // F.2.6 CBC-AES256.Decrypt
        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("9cfc4e967edb808d679f777bc6702c7d");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("39f23369a9d9bacfa530e26304231461");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("b2eb05e2c39be9fcda6c19078c6a9d1b");
        assertArrayEquals(ptext, decrypt(cipher, ctext));
    }

    @Test
    public void rfc3602() throws Exception {
        byte[] key, iv, pt, ct;

        // Case #1: Encrypting 16 bytes (1 block) using AES-CBC with 128-bit key
        key = hex("0x06a9214036b8a15b512e03d534120006");
        iv  = hex("0x3dafba429d9eb430b422da802c9fac41");
        pt  = "Single block msg".getBytes("US-ASCII");
        ct  = hex("0xe353779c1079aeb82708942dbe77181a");
        assertArrayEquals(ct, encrypt(key, iv, pt));

        // Case #2: Encrypting 32 bytes (2 blocks) using AES-CBC with 128-bit key
        key = hex("0xc286696d887c9aa0611bbb3e2025a45a");
        iv  = hex("0x562e17996d093d28ddb3ba695a2e6f58");
        pt  = hex("0x000102030405060708090a0b0c0d0e0f" +
                  "  101112131415161718191a1b1c1d1e1f");
        ct  = hex("0xd296cd94c2cccf8a3a863028b5e1dc0a" +
                  "  7586602d253cfff91b8266bea6d61ab1");
        assertArrayEquals(ct, encrypt(key, iv, pt));

        // Case #3: Encrypting 48 bytes (3 blocks) using AES-CBC with 128-bit key
        key = hex("0x6c3ea0477630ce21a2ce334aa746c2cd");
        iv  = hex("0xc782dc4c098c66cbd9cd27d825682c81");
        pt  = "This is a 48-byte message (exactly 3 AES blocks)".getBytes("US-ASCII");
        ct  = hex("0xd0a02b3836451753d493665d33f0e886" +
                  "  2dea54cdb293abc7506939276772f8d5" +
                  "  021c19216bad525c8579695d83ba2684");
        assertArrayEquals(ct, encrypt(key, iv, pt));

        // Case #4: Encrypting 64 bytes (4 blocks) using AES-CBC with 128-bit key
        key = hex("0x56e47a38c5598974bc46903dba290349");
        iv  = hex("0x8ce82eefbea0da3c44699ed7db51b7d9");
        pt  = hex("0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
                  "  b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                  "  c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                  "  d0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
        ct  = hex("0xc30e32ffedc0774e6aff6af0869f71aa" +
                  "  0f3af07a9a31a9c684db207eb0ef8e4e" +
                  "  35907aa632c3ffdf868bb7b29d3d46ad" +
                  "  83ce9f9a102ee99d49a53e87f4c3da55");
        assertArrayEquals(ct, encrypt(key, iv, pt));
    }

    @Test
    public void reset() throws Exception {
        byte[] key, iv, ptext, ctext;
        Cipher cipher;

        key    = hex("2b7e151628aed2a6abf7158809cf4f3c");
        iv     = hex("000102030405060708090a0b0c0d0e0f");
        cipher = Crypto.cipher(AES, CBC, key, iv);

        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("7649abac8119b246cee98e9b12e9197d");

        assertArrayEquals(ctext, encrypt(cipher, ptext));
        cipher.reset(iv);
        assertArrayEquals(ctext, encrypt(cipher, ptext));
    }

    public byte[] encrypt(Cipher cipher, byte[] pt) {
        byte[] bytes = new byte[pt.length];
        System.arraycopy(pt, 0, bytes, 0, pt.length);
        cipher.encrypt(bytes, bytes.length);
        return bytes;
    }

    public byte[] decrypt(Cipher cipher, byte[] pt) {
        byte[] bytes = new byte[pt.length];
        System.arraycopy(pt, 0, bytes, 0, pt.length);
        cipher.decrypt(bytes, bytes.length);
        return bytes;
    }

    public byte[] encrypt(byte[] key, byte[] iv, byte[] pt) {
        byte[] bytes = new byte[pt.length];
        System.arraycopy(pt, 0, bytes, 0, pt.length);
        Cipher cipher = Crypto.cipher(AES, CBC, key, iv);
        cipher.encrypt(bytes, bytes.length);
        return bytes;
    }
}
