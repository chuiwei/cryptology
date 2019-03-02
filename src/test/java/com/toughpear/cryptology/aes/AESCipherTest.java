package com.toughpear.cryptology.aes;

import com.toughpear.cryptology.util.KeyGenerator;
import com.toughpear.cryptology.util.KeyStore;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;

public class AESCipherTest {

    private final String testtext = "世界人民大团结！";
    private KeyGenerator keyGenerator = new KeyGenerator();

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
    public void decryptFromBase64Test() throws Exception {
        KeyStore keyStore = keyGenerator.getKeyStore();
        Key key = keyStore.getKey(keyGenerator.keyAlias, keyGenerator.keyPass);
        rightCharset(key);
        wrongCharset(key);
    }

    private void rightCharset(Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipher.doFinal(testtext.getBytes("UTF-8"));
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] encode = encoder.encode(bytes);
        AESCipher aesCipher = AESCipher.getInstance(key);
        String gbk = aesCipher.decryptFromBase64(new String(encode, "GBK"));
        assertEquals(gbk, testtext);
        AESCipher aesCipher2 = AESCipher.getInstance(key);
        String UTF8 = aesCipher2.decryptFromBase64(new String(encode, "UTF-8"));
        assertEquals(UTF8, testtext);
    }
    private void wrongCharset(Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipher.doFinal(testtext.getBytes("GBK"));
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] encode = encoder.encode(bytes);
        /**
         * 将密文以GBK编码
         */
        AESCipher aesCipher = AESCipher.getInstance(key);
        String gbk = aesCipher.decryptFromBase64(new String(encode, "GBK"));
        assertNotEquals(gbk, testtext);
        /**
        将密文以UTF-8编码后解密
         */
        AESCipher aesCipher2 = AESCipher.getInstance(key);
        String UTF8 = aesCipher2.decryptFromBase64(new String(encode, "UTF-8"));
        assertNotEquals(UTF8, testtext);
        /**
         将密文以GBK编码后解密
         */
        AESCipher aesCipher3 = AESCipher.getInstance(key);
        aesCipher3.setPlainCharset("GBK");
        String GBK = aesCipher3.decryptFromBase64(new String(encode));
        assertEquals(GBK, testtext);

        byte[] tmp = testtext.getBytes("GBK");
        String result = new String(tmp, "GBK");
        assertEquals(result, testtext);
    }

    @Test
    public void encryptToBase64Test() throws Exception {
        KeyStore keyStore = keyGenerator.getKeyStore();
        Key key = keyStore.getKey(keyGenerator.keyAlias, keyGenerator.keyPass);
        UTF8Encode(key);
        UTF8Encode_VS_GBK(key);
        GBKEncode_VS_GBK(key);
        EncodeToGBK(key);
    }
    private void UTF8Encode(Key key) throws Exception{
        AESCipher cipher = AESCipher.getInstance(key);
        String result = cipher.encryptToBase64(testtext);
        Cipher cipherChecker = Cipher.getInstance("AES");
        cipherChecker.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipherChecker.doFinal(testtext.getBytes("UTF-8"));
        Base64.Encoder base64 = Base64.getEncoder();
        byte[] encode = base64.encode(bytes);
        assertEquals(new String(encode), result);
    }

    private void UTF8Encode_VS_GBK(Key key) throws Exception {
        AESCipher cipher = AESCipher.getInstance(key);
        String result = cipher.encryptToBase64(testtext);
        Cipher cipherChecker = Cipher.getInstance("AES");
        cipherChecker.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipherChecker.doFinal(testtext.getBytes("GBK"));
        Base64.Encoder base64 = Base64.getEncoder();
        byte[] encode = base64.encode(bytes);
        assertNotEquals(new String(encode), result);
    }
    private void GBKEncode_VS_GBK(Key key) throws Exception {
        AESCipher cipher = AESCipher.getInstance(key);
        cipher.setPlainCharset("GBK");
        String result = cipher.encryptToBase64(testtext);
        Cipher cipherChecker = Cipher.getInstance("AES");
        cipherChecker.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipherChecker.doFinal(testtext.getBytes("GBK"));
        Base64.Encoder base64 = Base64.getEncoder();
        byte[] encode = base64.encode(bytes);
        assertEquals(new String(encode), result);
    }
    private void EncodeToGBK(Key key) throws Exception {
        EncodeToGBK_same(key);
        EncodeToGBK_diff(key);
    }

    private void EncodeToGBK_same(Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        AESCipher cipher = AESCipher.getInstance(key);
        cipher.setCipherCharset("GBK");
        String result = cipher.encryptToBase64(testtext);
        Cipher cipherChecker = Cipher.getInstance("AES");
        cipherChecker.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipherChecker.doFinal(testtext.getBytes("UTF-8"));
        Base64.Encoder base64 = Base64.getEncoder();
        byte[] encode = base64.encode(bytes);
        assertEquals(new String(encode, "GBK"), result);
    }
    private void EncodeToGBK_diff(Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        AESCipher cipher = AESCipher.getInstance(key);
        cipher.setCipherCharset("GBK");
        String result = cipher.encryptToBase64(testtext);
        Cipher cipherChecker = Cipher.getInstance("AES");
        cipherChecker.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipherChecker.doFinal(testtext.getBytes("UTF-8"));
        Base64.Encoder base64 = Base64.getEncoder();
        byte[] encode = base64.encode(bytes);
        assertEquals(new String(encode, "UTF-8"), result);
    }

    @Test
    public void Base64IgnoreCharset() throws Exception{
        Base64.Encoder base64 = Base64.getEncoder();
        byte[] encode = base64.encode(this.testtext.getBytes("UTF-8"));
        assertEquals(new String(encode, "GBK"), new String(encode, "UTF-8"));
    }
}
