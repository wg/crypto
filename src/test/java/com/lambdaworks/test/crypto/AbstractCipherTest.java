// Copyright (C) 2012 - Will Glozer.  All rights reserved.

package com.lambdaworks.test.crypto;

import com.lambdaworks.test.codec.Base16;

public abstract class AbstractCipherTest {
    public byte[] hex(String s) {
        s = s.replaceAll("(^0x|\\s+)", "");
        return Base16.decode(s.toCharArray());
    }
}
