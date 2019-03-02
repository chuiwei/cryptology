package com.toughpear.cryptology.aes;

import com.toughpear.cryptology.exception.CryptException;
import com.toughpear.cryptology.util.KeyStore;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESCipher {
    private Key aesKey;
    private String plainCharset="UTF-8";
    private String cipherCharset = "UTF-8";
    public static AESCipher getInstance(Key aesKey){
        return new AESCipher(aesKey);
    }
    private AESCipher(Key aesKey){
        this.aesKey = aesKey;
    }

    public void setPlainCharset(String charset){
        this.plainCharset = charset;
    }
    public void setCipherCharset(String charset){
        this.cipherCharset = charset;
    }
    public String encryptToBase64(String plain){
        byte[] bytes = encrypt(plain);
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] encode = encoder.encode(bytes);
        try {
            return new String(encode, cipherCharset);
        } catch (UnsupportedEncodingException e) {
            throw new CryptException(e);
        }
    }

    public String decryptFromBase64(String cipherText){
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] cipherBytes = decoder.decode(cipherText);
        byte[] plain = decrypt(cipherBytes);
        try {
            return new String(plain, plainCharset);
        } catch (UnsupportedEncodingException e) {
            throw new CryptException(e);
        }
    }
    private byte[] decrypt(byte[] cipherBytes){
        try {
            Cipher decrypt = Cipher.getInstance("AES");
            decrypt.init(Cipher.DECRYPT_MODE, aesKey);
            return decrypt.doFinal(cipherBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            throw new CryptException(e);
        }
    }

    private byte[] encrypt(String plain){
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] bytes = cipher.doFinal(plain.getBytes(plainCharset));
            return bytes;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new CryptException(e);
        }
    }
}
