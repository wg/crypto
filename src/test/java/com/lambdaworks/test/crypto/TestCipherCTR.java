// Copyright (C) 2012 - Will Glozer.  All rights reserved.

package com.lambdaworks.test.crypto;

import com.lambdaworks.crypto.Cipher;
import com.lambdaworks.crypto.Crypto;
import org.junit.Test;

import static org.junit.Assert.*;
import static com.lambdaworks.crypto.Cipher.Algorithm.*;
import static com.lambdaworks.crypto.Cipher.Mode.*;

public class TestCipherCTR extends AbstractCipherTest {
    /**
     * NIST SP800-30A test vectors.
     *
     * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
     */
    @Test
    public void nist_sp800_38a() throws Exception {
        byte[] key, icb, ptext, ctext;
        Cipher cipher;

        // F.5.1 CTR-AES128.Encrypt
        // NOTE: published test vector ICB ends in 0xff, but this
        //       CTR implementation increments before encrypting
        key    = hex("2b7e151628aed2a6abf7158809cf4f3c");
        icb    = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefe");
        cipher = Crypto.cipher(AES, CTR, key, icb);
        
        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("874d6191b620e3261bef6864990db6ce");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("9806f66b7970fdff8617187bb9fffdff");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("5ae4df3edbd5d35e5b4f09020db03eab");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("1e031dda2fbe03d1792170a0f3009cee");
        assertArrayEquals(ctext, encrypt(cipher, ptext));
                
        cipher = Crypto.cipher(AES, CTR, key, icb);
        
        // F.5.2 CTR-AES128.Decrypt
        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("874d6191b620e3261bef6864990db6ce");
        assertArrayEquals(ctext, decrypt(cipher, ptext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("9806f66b7970fdff8617187bb9fffdff");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("5ae4df3edbd5d35e5b4f09020db03eab");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("1e031dda2fbe03d1792170a0f3009cee");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // F.5.3 CTR-AES192.Encrypt
        // NOTE: published test vector ICB ends in 0xff, but this
        //       CTR implementation increments before encrypting
        key    = hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        icb    = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefe");
        cipher = Crypto.cipher(AES, CTR, key, icb);
        
        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("1abc932417521ca24f2b0459fe7e6e0b");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("090339ec0aa6faefd5ccc2c6f4ce8e94");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("1e36b26bd1ebc670d1bd1d665620abf7");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("4f78a7f6d29809585a97daec58c6b050");
        assertArrayEquals(ctext, encrypt(cipher, ptext));
              
        cipher = Crypto.cipher(AES, CTR, key, icb);
        
        // F.5.4 CTR-AES192.Decrypt
        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("1abc932417521ca24f2b0459fe7e6e0b");
        assertArrayEquals(ctext, decrypt(cipher, ptext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("090339ec0aa6faefd5ccc2c6f4ce8e94");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("1e36b26bd1ebc670d1bd1d665620abf7");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("4f78a7f6d29809585a97daec58c6b050");
        assertArrayEquals(ptext, decrypt(cipher, ctext));
        
        // F.5.5 CTR-AES256.Encrypt
        // NOTE: published test vector ICB ends in 0xff, but this
        //       CTR implementation increments before encrypting
        key    = hex("603deb1015ca71be2b73aef0857d7781" +
                     "1f352c073b6108d72d9810a30914dff4");
        icb    = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefe");
        cipher = Crypto.cipher(AES, CTR, key, icb);
        
        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("601ec313775789a5b7a7f504bbf3d228");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("f443e3ca4d62b59aca84e990cacaf5c5");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("2b0930daa23de94ce87017ba2d84988d");
        assertArrayEquals(ctext, encrypt(cipher, ptext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("dfc9c58db67aada613c2dd08457941a6");
        assertArrayEquals(ctext, encrypt(cipher, ptext));
              
        cipher = Crypto.cipher(AES, CTR, key, icb);
        
        // F.5.6 CTR-AES256.Decrypt
        // Block #1
        ptext = hex("6bc1bee22e409f96e93d7e117393172a");
        ctext = hex("601ec313775789a5b7a7f504bbf3d228");
        assertArrayEquals(ctext, decrypt(cipher, ptext));

        // Block #2
        ptext = hex("ae2d8a571e03ac9c9eb76fac45af8e51");
        ctext = hex("f443e3ca4d62b59aca84e990cacaf5c5");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #3
        ptext = hex("30c81c46a35ce411e5fbc1191a0a52ef");
        ctext = hex("2b0930daa23de94ce87017ba2d84988d");
        assertArrayEquals(ptext, decrypt(cipher, ctext));

        // Block #4
        ptext = hex("f69f2445df4f9b17ad2b417be66c3710");
        ctext = hex("dfc9c58db67aada613c2dd08457941a6");
        assertArrayEquals(ptext, decrypt(cipher, ctext));
    }

    /**
     * RFC 3686 test vectors.
     *
     * http://www.faqs.org/rfcs/rfc3686.html
     */
    @Test
    public void rfc3686() throws Exception {
        byte[] key, input, iv, nonce, ctext;

        // Test Vector #1: Encrypting 16 octets using AES-CTR with 128-bit key
        key   = hex("AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E");
        iv    = hex("00 00 00 00 00 00 00 00");
        nonce = hex("00 00 00 30");
        input = hex("53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67");
        ctext = hex("E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8");
        assertArrayEquals(ctext, encrypt(key, ctr(nonce, iv, 0), input));

        // Test Vector #2: Encrypting 32 octets using AES-CTR with 128-bit key
        key   = hex("7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63");
        iv    = hex("C0 54 3B 59 DA 48 D9 0B");
        nonce = hex("00 6C B6 DB");
        input = hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" +
                    "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");
        ctext = hex("51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88" +
                    "EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28");
        assertArrayEquals(ctext, encrypt(key, ctr(nonce, iv, 0), input));

        // Test Vector #3: Encrypting 36 octets using AES-CTR with 128-bit key
        key   = hex("76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC");
        iv    = hex("27 77 7F 3F  4A 17 86 F0");
        nonce = hex("00 E0 01 7B");
        input = hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" +
                    "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F" +
                    "20 21 22 23");
        ctext = hex("C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7" +
                    "45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53" +
                    "25 B2 07 2F");
        assertArrayEquals(ctext, encrypt(key, ctr(nonce, iv, 0), input));

        // Test Vector #4: Encrypting 16 octets using AES-CTR with 192-bit key
        key   = hex("16 AF 5B 14 5F C9 F5 79 C1 75 F9 3E 3B FB 0E ED" +
                    "86 3D 06 CC FD B7 85 15");
        iv    = hex("36 73 3C 14 7D 6D 93 CB");
        nonce = hex("00 00 00 48");
        input = hex("53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67");
        ctext = hex("4B 55 38 4F E2 59 C9 C8 4E 79 35 A0 03 CB E9 28");
        assertArrayEquals(ctext, encrypt(key, ctr(nonce, iv, 0), input));

        // Test Vector #5: Encrypting 32 octets using AES-CTR with 192-bit key
        key   = hex("7C 5C B2 40 1B 3D C3 3C 19 E7 34 08 19 E0 F6 9C" +
                    "67 8C 3D B8 E6 F6 A9 1A");
        iv    = hex("02 0C 6E AD C2 CB 50 0D");
        nonce = hex("00 96 B0 3B");
        input = hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" +
                    "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");
        ctext = hex("45 32 43 FC 60 9B 23 32 7E DF AA FA 71 31 CD 9F" +
                    "84 90 70 1C 5A D4 A7 9C FC 1F E0 FF 42 F4 FB 00");
        assertArrayEquals(ctext, encrypt(key, ctr(nonce, iv, 0), input));

        // Test Vector #6: Encrypting 36 octets using AES-CTR with 192-bit key
        key   = hex("02 BF 39 1E E8 EC B1 59 B9 59 61 7B 09 65 27 9B" +
                       "F5 9B 60 A7 86 D3 E0 FE");
        iv    = hex("5C BD 60 27 8D CC 09 12");
        nonce = hex("00 07 BD FD");
        input = hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" +
                    "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F" +
                    "20 21 22 23");
        ctext = hex("96 89 3F C5 5E 5C 72 2F 54 0B 7D D1 DD F7 E7 58" +
                    "D2 88 BC 95 C6 91 65 88 45 36 C8 11 66 2F 21 88" +
                    "AB EE 09 35");
        assertArrayEquals(ctext, encrypt(key, ctr(nonce, iv, 0), input));

        // Test Vector #7: Encrypting 16 octets using AES-CTR with 256-bit key
        key   = hex("77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C" +
                    "6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04");
        iv    = hex("DB 56 72 C9 7A A8 F0 B2");
        nonce = hex("00 00 00 60");
        input = hex("53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67");
        ctext = hex("14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0");
        assertArrayEquals(ctext, encrypt(key, ctr(nonce, iv, 0), input));

        // Test Vector #8: Encrypting 32 octets using AES-CTR with 256-bit key
        key   = hex("F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86" +
                    "C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84");
        iv    = hex("C1 58 5E F1 5A 43 D8 75");
        nonce = hex("00 FA AC 24");
        input = hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" +
                    "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");
        ctext = hex("F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9" +
                    "B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C");
        assertArrayEquals(ctext, encrypt(key, ctr(nonce, iv, 0), input));

        // Test Vector #9: Encrypting 36 octets using AES-CTR with 256-bit key
        key   = hex("FF 7A 61 7C E6 91 48 E4 F1 72 6E 2F 43 58 1D E2" +
                    "AA 62 D9 F8 05 53 2E DF F1 EE D6 87 FB 54 15 3D");
        iv    = hex("51 A5 1D 70 A1 C1 11 48");
        nonce = hex("00 1C C5 B7");
        input = hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" +
                    "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F" +
                    "20 21 22 23");
        ctext = hex("EB 6C 52 82 1D 0B BB F7 CE 75 94 46 2A CA 4F AA" +
                    "B4 07 DF 86 65 69 FD 07 F4 8C C0 B5 83 D6 07 1F" +
                    "1E C0 E6 B8");
        assertArrayEquals(ctext, encrypt(key, ctr(nonce, iv, 0), input));
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

    private byte[] ctr(byte[] nonce, byte[] iv, int ctr) {
        byte[] bytes = new byte[16];
        System.arraycopy(nonce, 0, bytes, 0, 4);
        System.arraycopy(iv,    0, bytes, 4, 8);
        bytes[12] = (byte) (ctr >> 24 & 0xff);
        bytes[13] = (byte) (ctr >> 16 & 0xff);
        bytes[14] = (byte) (ctr >>  8 & 0xff);
        bytes[15] = (byte) (ctr       & 0xff);
        return bytes;
    }

    public byte[] encrypt(byte[] key, byte[] icb, byte[] pt) {
        Cipher cipher = Crypto.cipher(AES, CTR, key, icb);
        return encrypt(cipher, pt);
    }
}
