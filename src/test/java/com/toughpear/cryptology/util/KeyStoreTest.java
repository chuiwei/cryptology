package com.toughpear.cryptology.util;

import com.toughpear.cryptology.exception.CryptException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import static org.junit.Assert.*;

public class KeyStoreTest {

    private com.toughpear.cryptology.util.KeyGenerator keyGenerator = new com.toughpear.cryptology.util.KeyGenerator();

    @Before
    public void before() throws Exception {
        keyGenerator.generateAESKey();
    }

    @After
    public void after() throws Exception {
        File file = new File(this.getClass().getResource("/" + this.keyGenerator.storeFileName).getPath());
        file.delete();
        assertFalse(file.exists());
    }

    @Test
    public void getKeyEmpty() {
        KeyStore keyStore = new KeyStore();
        keyStore.setPath(this.getClass().getResource("/" + this.keyGenerator.storeFileName).getPath());
        keyStore.setStoreType(this.keyGenerator.storeType);
        keyStore.setStorePass(this.keyGenerator.storePass);
        keyStore.init();
        assertNull(keyStore.getKey(this.keyGenerator.keyAlias + "_1", this.keyGenerator.keyPass));
    }

    @Test
    public void getKeyRight() {
        KeyStore keyStore = new KeyStore();
        keyStore.setPath(this.getClass().getResource("/" + this.keyGenerator.storeFileName).getPath());
        keyStore.setStoreType(this.keyGenerator.storeType);
        keyStore.setStorePass(this.keyGenerator.storePass);
        keyStore.init();
        assertNotNull(keyStore.getKey(this.keyGenerator.keyAlias, this.keyGenerator.keyPass));
    }

    @Test(expected = CryptException.class)
    public void getKeyException() {
        KeyStore keyStore = new KeyStore();
        keyStore.setPath(this.getClass().getResource("/" + this.keyGenerator.storeFileName).getPath());
        keyStore.setStoreType("jks");
        keyStore.setStorePass(this.keyGenerator.storePass);
        keyStore.init();
    }
}
