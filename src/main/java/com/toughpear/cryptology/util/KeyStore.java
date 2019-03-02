package com.toughpear.cryptology.util;

import com.toughpear.cryptology.exception.CryptException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class KeyStore {
    private String path;
    private String storeType;
    private String storePass;
    private java.security.KeyStore ks;


    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getStoreType() {
        return storeType;
    }

    public void setStoreType(String storeType) {
        this.storeType = storeType;
    }

    public String getStorePass() {
        return storePass;
    }

    public void setStorePass(String storePass) {
        this.storePass = storePass;
    }
    public KeyStore(){
    }
    public KeyStore(String path, String storeType, String storePass){
        this.path = path;
        this.storeType = storeType;
        this.storePass = storePass;
        init();
    }

    public void init() {
        InputStream is = null;
        try {
            is = new FileInputStream(this.path);
            this.ks = java.security.KeyStore.getInstance(storeType);
            this.ks.load(is, storePass == null ? null : storePass.toCharArray());

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new CryptException(e);
        }finally {
            if(is != null){
                try {is.close();} catch (IOException e) {e.printStackTrace();}
            }
        }
    }

    public  Key getKey(String keyAlias, String keyPass) {
        try {
            Key key = ks.getKey(keyAlias, keyPass == null ? null : keyPass.toCharArray());
            return key;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new CryptException(e);
        }
    }
}
