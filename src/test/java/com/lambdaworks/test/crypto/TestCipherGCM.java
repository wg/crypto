// Copyright (C) 2012 - Will Glozer.  All rights reserved.

package com.lambdaworks.test.crypto;

import com.lambdaworks.crypto.Cipher;
import com.lambdaworks.crypto.Crypto;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;
import static com.lambdaworks.crypto.Cipher.Algorithm.*;
import static com.lambdaworks.crypto.Cipher.Mode.*;

public class TestCipherGCM extends AbstractCipherTest {
    /**
     * Test vectors from "The Galois/Counter Mode of Operation (GCM)" NIST proposal.
     *
     * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
     */
    @Test
    public void nist_proposal() throws Exception {
        byte[] key, input, iv, aad, tag, ctext, data;

        // Test Case 1
        key   = hex("00000000000000000000000000000000");
        input = hex("");
        iv    = hex("000000000000000000000000");
        aad   = hex("");
        ctext = hex("");
        tag   = hex("58e2fccefa7e3061367f1d57a4e7455a");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 2
        key   = hex("00000000000000000000000000000000");
        input = hex("00000000000000000000000000000000");
        aad   = hex("");
        iv    = hex("000000000000000000000000");
        ctext = hex("0388dace60b6a392f328c2b971b2fe78");
        tag   = hex("ab6e47d42cec13bdf53a67b21257bddf");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 3
        key   = hex("feffe9928665731c6d6a8f9467308308");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b391aafd255");
        aad   = hex("");
        iv    = hex("cafebabefacedbaddecaf888");
        ctext = hex("42831ec2217774244b7221b784d0d49c" +
                    "e3aa212f2c02a4e035c17e2329aca12e" +
                    "21d514b25466931c7d8f6a5aac84aa05" +
                    "1ba30b396a0aac973d58e091473f5985");
        tag   = hex("4d5c2af327cd64a62cf35abd2ba6fab4");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 4
        key   = hex("feffe9928665731c6d6a8f9467308308");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("cafebabefacedbaddecaf888");
        ctext = hex("42831ec2217774244b7221b784d0d49c" +
                    "e3aa212f2c02a4e035c17e2329aca12e" +
                    "21d514b25466931c7d8f6a5aac84aa05" +
                    "1ba30b396a0aac973d58e091");
        tag   = hex("5bc94fbc3221a5db94fae95ae7121a47");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 5
        key   = hex("feffe9928665731c6d6a8f9467308308");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("cafebabefacedbad");
        ctext = hex("61353b4c2806934a777ff51fa22a4755" +
                    "699b2a714fcdc6f83766e5f97b6c7423" +
                    "73806900e49f24b22b097544d4896b42" +
                    "4989b5e1ebac0f07c23f4598");
        tag   = hex("3612d2e79e3b0785561be14aaca2fccb");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 6
        key   = hex("feffe9928665731c6d6a8f9467308308");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("9313225df88406e555909c5aff5269aa" +
                    "6a7a9538534f7da1e4c303d2a318a728" +
                    "c3c0c95156809539fcf0e2429a6b5254" +
                    "16aedbf5a0de6a57a637b39b");
        ctext = hex("8ce24998625615b603a033aca13fb894" +
                    "be9112a5c3a211a8ba262a3cca7e2ca7" +
                    "01e4a9a4fba43c90ccdcb281d48c7c6f" +
                    "d62875d2aca417034c34aee5");
        tag   = hex("619cc5aefffe0bfa462af43c1699d050");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 7
        key   = hex("00000000000000000000000000000000" +
                    "0000000000000000");
        input = hex("");
        aad   = hex("");
        iv    = hex("000000000000000000000000");
        ctext = hex("");
        tag   = hex("cd33b28ac773f74ba00ed1f312572435");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 8
        key   = hex("00000000000000000000000000000000" +
                    "0000000000000000");
        input = hex("00000000000000000000000000000000");
        aad   = hex("");
        iv    = hex("000000000000000000000000");
        ctext = hex("98e7247c07f0fe411c267e4384b0f600");
        tag   = hex("2ff58d80033927ab8ef4d4587514f0fb");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 9
        key   = hex("feffe9928665731c6d6a8f9467308308" +
                    "feffe9928665731c");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b391aafd255");
        aad   = hex("");
        iv    = hex("cafebabefacedbaddecaf888");
        ctext = hex("3980ca0b3c00e841eb06fac4872a2757" +
                    "859e1ceaa6efd984628593b40ca1e19c" +
                    "7d773d00c144c525ac619d18c84a3f47" +
                    "18e2448b2fe324d9ccda2710acade256");
        tag   = hex("9924a7c8587336bfb118024db8674a14");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 10
        key   = hex("feffe9928665731c6d6a8f9467308308" +
                    "feffe9928665731c");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("cafebabefacedbaddecaf888");
        ctext = hex("3980ca0b3c00e841eb06fac4872a2757" +
                    "859e1ceaa6efd984628593b40ca1e19c" +
                    "7d773d00c144c525ac619d18c84a3f47" +
                    "18e2448b2fe324d9ccda2710");
        tag   = hex("2519498e80f1478f37ba55bd6d27618c");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 11
        key   = hex("feffe9928665731c6d6a8f9467308308" +
                    "feffe9928665731c");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("cafebabefacedbad");
        ctext = hex("0f10f599ae14a154ed24b36e25324db8" +
                    "c566632ef2bbb34f8347280fc4507057" +
                    "fddc29df9a471f75c66541d4d4dad1c9" +
                    "e93a19a58e8b473fa0f062f7");
        tag   = hex("65dcc57fcf623a24094fcca40d3533f8");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 12
        key   = hex("feffe9928665731c6d6a8f9467308308" +
                    "feffe9928665731c");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("9313225df88406e555909c5aff5269aa" +
                    "6a7a9538534f7da1e4c303d2a318a728" +
                    "c3c0c95156809539fcf0e2429a6b5254" +
                    "16aedbf5a0de6a57a637b39b");
        ctext = hex("d27e88681ce3243c4830165a8fdcf9ff" +
                    "1de9a1d8e6b447ef6ef7b79828666e45" +
                    "81e79012af34ddd9e2f037589b292db3" +
                    "e67c036745fa22e7e9b7373b");
        tag   = hex("dcf566ff291c25bbb8568fc3d376a6d9");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 13
        key   = hex("00000000000000000000000000000000" +
                    "00000000000000000000000000000000");
        input = hex("");
        aad   = hex("");
        iv    = hex("000000000000000000000000");
        ctext = hex("");
        tag   = hex("530f8afbc74536b9a963b4f1c4cb738b");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 14
        key   = hex("00000000000000000000000000000000" +
                    "00000000000000000000000000000000");
        input = hex("00000000000000000000000000000000");
        aad   = hex("");
        iv    = hex("000000000000000000000000");
        ctext = hex("cea7403d4d606b6e074ec5d3baf39d18");
        tag   = hex("d0d1c8a799996bf0265b98b5d48ab919");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 15
        key   = hex("feffe9928665731c6d6a8f9467308308" +
                    "feffe9928665731c6d6a8f9467308308");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b391aafd255");
        aad   = hex("");
        iv    = hex("cafebabefacedbaddecaf888");
        ctext = hex("522dc1f099567d07f47f37a32a84427d" +
                    "643a8cdcbfe5c0c97598a2bd2555d1aa" +
                    "8cb08e48590dbb3da7b08b1056828838" +
                    "c5f61e6393ba7a0abcc9f662898015ad");
        tag   = hex("b094dac5d93471bdec1a502270e3cc6c");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 16
        key   = hex("feffe9928665731c6d6a8f9467308308" +
                    "feffe9928665731c6d6a8f9467308308");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("cafebabefacedbaddecaf888");
        ctext = hex("522dc1f099567d07f47f37a32a84427d" +
                    "643a8cdcbfe5c0c97598a2bd2555d1aa" +
                    "8cb08e48590dbb3da7b08b1056828838" +
                    "c5f61e6393ba7a0abcc9f662");
        tag   = hex("76fc6ece0f4e1768cddf8853bb2d551b");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 17
        key   = hex("feffe9928665731c6d6a8f9467308308" +
                    "feffe9928665731c6d6a8f9467308308");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("cafebabefacedbad");
        ctext = hex("c3762df1ca787d32ae47c13bf19844cb" +
                    "af1ae14d0b976afac52ff7d79bba9de0" +
                    "feb582d33934a4f0954cc2363bc73f78" +
                    "62ac430e64abe499f47c9b1f");
        tag   = hex("3a337dbf46a792c45e454913fe2ea8f2");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));

        // Test Case 18
        key   = hex("feffe9928665731c6d6a8f9467308308" +
                    "feffe9928665731c6d6a8f9467308308");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("9313225df88406e555909c5aff5269aa" +
                    "6a7a9538534f7da1e4c303d2a318a728" +
                    "c3c0c95156809539fcf0e2429a6b5254" +
                    "16aedbf5a0de6a57a637b39b");
        ctext = hex("5a8def2f0c9e53f1f75d7853659e2a20" +
                    "eeb2b22aafde6419a058ab4f6f746bf4" +
                    "0fc0c3b780f244452da3ebf1c5d82cde" +
                    "a2418997200ef82e44ae7e3f");
        tag   = hex("a44a8266ee1c8eb0c8b5d4cf5ae9f19a");
        data  = encrypt(key, iv, aad, input);
        assertArrayEquals(ctext, ciphertext(data));
        assertArrayEquals(tag, tag(data));
        data  = decrypt(key, iv, aad, ctext);
        assertArrayEquals(input, ciphertext(data));
        assertArrayEquals(tag, tag(data));
    }

    @Test
    public void reset() throws Exception {
        byte[] key, input, iv, aad;

        key   = hex("feffe9928665731c6d6a8f9467308308");
        input = hex("d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39");
        aad   = hex("feedfacedeadbeeffeedfacedeadbeef" +
                    "abaddad2");
        iv    = hex("cafebabefacedbaddecaf888");

        Cipher cipher = Crypto.cipher(AES, GCM, key, iv);
        cipher.aad(aad, aad.length);
        cipher.encrypt(Arrays.copyOf(input, input.length), input.length);
        byte[] tag = cipher.mac();
        cipher.reset(iv);
        cipher.aad(aad, aad.length);
        cipher.encrypt(Arrays.copyOf(input, input.length), input.length);
        assertArrayEquals(tag, cipher.mac());
    }

    public byte[] encrypt(byte[] key, byte[] iv, byte[] aad, byte[] pt) throws Exception {
        byte[] bytes = new byte[pt.length];
        System.arraycopy(pt, 0, bytes, 0, pt.length);
        Cipher cipher = Crypto.cipher(AES, GCM, key, iv);
        if (aad.length > 0) cipher.aad(aad, aad.length);
        if (pt.length  > 0) cipher.encrypt(bytes, bytes.length);

        byte[] tag = cipher.mac();
        byte[] output = new byte[pt.length + tag.length];
        System.arraycopy(bytes, 0, output, 0, pt.length);
        System.arraycopy(tag,   0, output, pt.length, 16);

        return output;
    }

    public byte[] decrypt(byte[] key, byte[] iv, byte[] aad, byte[] ct) throws Exception {
        byte[] bytes = new byte[ct.length];
        System.arraycopy(ct, 0, bytes, 0, ct.length);
        Cipher cipher = Crypto.cipher(AES, GCM, key, iv);
        if (aad.length > 0) cipher.aad(aad, aad.length);
        if (ct.length  > 0) cipher.decrypt(bytes, bytes.length);

        byte[] tag = cipher.mac();
        byte[] output = new byte[ct.length + tag.length];
        System.arraycopy(bytes, 0, output, 0, ct.length);
        System.arraycopy(tag,   0, output, ct.length, 16);

        return output;
    }

    public byte[] ciphertext(byte[] data) {
        byte[] ciphertext = new byte[data.length - 16];
        System.arraycopy(data, 0, ciphertext, 0, ciphertext.length);
        return ciphertext;
    }

    public byte[] tag(byte[] data) {
        byte[] tag = new byte[16];
        System.arraycopy(data, data.length - 16, tag, 0, 16);
        return tag;
    }
}
