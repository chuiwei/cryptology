package com.toughpear.cryptology.util;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class KeyGenerator {
    public final String storeType = "jceks";
    public final String storeFileName = "testkeystore.keystore";
    public final String storePass = "12345678";
    public final String keyPass = "keypass";
    public final String keyAlias = "testkey";
    public final String keyType = "AES";

    public void generateAESKey() throws Exception {
        javax.crypto.KeyGenerator keygen = javax.crypto.KeyGenerator.getInstance(this.keyType);
        SecureRandom random = new SecureRandom();
        keygen.init(random);
        SecretKey secretKey = keygen.generateKey();
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance(this.storeType);
        keyStore.load(null, null);
        keyStore.setKeyEntry(this.keyAlias, secretKey, this.keyPass.toCharArray(), null);
        String path = this.getClass().getResource("/").getPath() + this.storeFileName;
        File file = new File(path);
        OutputStream outputStream = new FileOutputStream(path);
        keyStore.store(outputStream, this.storePass.toCharArray());
        outputStream.close();
    }
    public KeyStore getKeyStore(){
        KeyStore keyStore = new KeyStore();
        keyStore.setPath(this.getClass().getResource("/").getPath()+this.storeFileName);
        keyStore.setStorePass(this.storePass);
        keyStore.setStoreType(this.storeType);
        keyStore.init();
        return keyStore;
    }

}
