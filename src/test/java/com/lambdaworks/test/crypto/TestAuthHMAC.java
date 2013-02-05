// Copyright (C) 2012 - Will Glozer.  All rights reserved.

package com.lambdaworks.test.crypto;

import com.lambdaworks.crypto.Cipher;
import com.lambdaworks.crypto.Crypto;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;
import static com.lambdaworks.crypto.Cipher.Algorithm.*;
import static com.lambdaworks.crypto.Cipher.Mac.*;
import static com.lambdaworks.crypto.Cipher.Mode.*;

public class TestAuthHMAC extends AbstractCipherTest {
    @Test
    public void rfc4231() throws Exception {
        byte[] key, data, sha256, sha512;

        // 4.2.  Test Case 1
        key    = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" +
                     "0b0b0b0b");
        data   = hex("4869205468657265");
        sha256 = hex("b0344c61d8db38535ca8afceaf0bf12b" +
                     "881dc200c9833da726e9376c2e32cff7");
        sha512 = hex("87aa7cdea5ef619d4ff0b4241a1d6cb0" +
                     "2379f4e2ce4ec2787ad0b30545e17cde" +
                     "daa833b7d6b8a702038b274eaea3f4e4" +
                     "be9d914eeb61f1702e696c203a126854");
        assertArrayEquals(sha256, hmac(SHA2, 256, key, data));
        assertArrayEquals(sha512, hmac(SHA2, 512, key, data));

        // 4.3.  Test Case 2
        key    = hex("4a656665");
        data   = hex("7768617420646f2079612077616e7420" +
                     "666f72206e6f7468696e673f");
        sha256 = hex("5bdcc146bf60754e6a042426089575c7" +
                     "5a003f089d2739839dec58b964ec3843");
        sha512 = hex("164b7a7bfcf819e2e395fbe73b56e0a3" +
                     "87bd64222e831fd610270cd7ea250554" +
                     "9758bf75c05a994a6d034f65f8f0e6fd" +
                     "caeab1a34d4a6b4b636e070a38bce737");
        assertArrayEquals(sha256, hmac(SHA2, 256, key, data));
        assertArrayEquals(sha512, hmac(SHA2, 512, key, data));

        // 4.4.  Test Case 3
        key    = hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaa");
        data   = hex("dddddddddddddddddddddddddddddddd" +
                     "dddddddddddddddddddddddddddddddd" +
                     "dddddddddddddddddddddddddddddddd" +
                     "dddd");
        sha256 = hex("773ea91e36800e46854db8ebd09181a7" +
                     "2959098b3ef8c122d9635514ced565fe");
        sha512 = hex("fa73b0089d56a284efb0f0756c890be9" +
                     "b1b5dbdd8ee81a3655f83e33b2279d39" +
                     "bf3e848279a722c806b485a47e67c807" +
                     "b946a337bee8942674278859e13292fb");
        assertArrayEquals(sha256, hmac(SHA2, 256, key, data));
        assertArrayEquals(sha512, hmac(SHA2, 512, key, data));

        // 4.5.  Test Case 4
        key    = hex("0102030405060708090a0b0c0d0e0f10" +
                     "111213141516171819");
        data   = hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
                     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
                     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
                     "cdcd");
        sha256 = hex("82558a389a443c0ea4cc819899f2083a" +
                     "85f0faa3e578f8077a2e3ff46729665b");
        sha512 = hex("b0ba465637458c6990e5a8c5f61d4af7" +
                     "e576d97ff94b872de76f8050361ee3db" +
                     "a91ca5c11aa25eb4d679275cc5788063" +
                     "a5f19741120c4f2de2adebeb10a298dd");
        assertArrayEquals(sha256, hmac(SHA2, 256, key, data));
        assertArrayEquals(sha512, hmac(SHA2, 512, key, data));

        // 4.6.  Test Case 5
        key    = hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" +
                     "0c0c0c0c");
        data   = hex("546573742057697468205472756e6361" +
                     "74696f6e");
        sha256 = hex("a3b6167473100ee06e0c796c2955552b");
        sha512 = hex("415fad6271580a531d4179bc891d87a6");
        assertArrayEquals(sha256, Arrays.copyOfRange(hmac(SHA2, 256, key, data), 0, 16));
        assertArrayEquals(sha512, Arrays.copyOfRange(hmac(SHA2, 512, key, data), 0, 16));

        // 4.7.  Test Case 6
        key    = hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaa");
        data   = hex("54657374205573696e67204c61726765" +
                     "72205468616e20426c6f636b2d53697a" +
                     "65204b6579202d2048617368204b6579" +
                     "204669727374");
        sha256 = hex("60e431591ee0b67f0d8a26aacbf5b77f" +
                     "8e0bc6213728c5140546040f0ee37f54");
        sha512 = hex("80b24263c7c1a3ebb71493c1dd7be8b4" +
                     "9b46d1f41b4aeec1121b013783f8f352" +
                     "6b56d037e05f2598bd0fd2215d6a1e52" +
                     "95e64f73f63f0aec8b915a985d786598");
        assertArrayEquals(sha256, hmac(SHA2, 256, key, data));
        assertArrayEquals(sha512, hmac(SHA2, 512, key, data));

        // 4.8.  Test Case 7
        key    = hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                     "aaaaaa");
        data   = hex("54686973206973206120746573742075" +
                     "73696e672061206c6172676572207468" +
                     "616e20626c6f636b2d73697a65206b65" +
                     "7920616e642061206c61726765722074" +
                     "68616e20626c6f636b2d73697a652064" +
                     "6174612e20546865206b6579206e6565" +
                     "647320746f2062652068617368656420" +
                     "6265666f7265206265696e6720757365" +
                     "642062792074686520484d414320616c" +
                     "676f726974686d2e");
        sha256 = hex("9b09ffa71b942fcb27635fbcd5b0e944" +
                     "bfdc63644f0713938a7f51535c3a35e2");
        sha512 = hex("e37b6a775dc87dbaa4dfa9f96e5e3ffd" +
                     "debd71f8867289865df5a32d20cdc944" +
                     "b6022cac3c4982b10d5eeb55c3e4de15" +
                     "134676fb6de0446065c97440fa8c6a58");
        assertArrayEquals(sha256, hmac(SHA2, 256, key, data));
        assertArrayEquals(sha512, hmac(SHA2, 512, key, data));
    }

    byte[] hmac(Cipher.Mac mac, int bits, byte[] key, byte[] data) {
        Cipher cipher = Crypto.cipher(AES, CBC, new byte[16], new byte[16]);
        cipher.authenticate(mac, bits, key);
        cipher.aad(data, data.length);
        return cipher.mac();
    }
}
