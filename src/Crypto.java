import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Crypto {
    static Cipher cipher;
    static String key = "aesEncryptionKey";
    static String iv = "encryptionIntVec";
    public static SecretKey  GenerateSessionKey() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
        return keygenerator.generateKey();
    }
    public static KeyPair generateKeyPair()
            throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static SecretKey createAESKey(String mobile)
            throws Exception {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

        KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(mobile.toCharArray() , key.getBytes() , 12288 , 256);
        SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
        return  new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), "AES");
    }

    public static byte[] encryptSession(String sessionKey , PublicKey KEY )
            throws Exception {
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, KEY);

        return cipher.doFinal(sessionKey.getBytes());
    }
    public static String decryptSession(byte[] sessionKey, PrivateKey KEY)
            throws Exception {
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,
                KEY);
        byte[] result
                = cipher.doFinal(sessionKey);

        return new String(result);
    }
    public static String encrypt(String plainText , SecretKey KEY  )
            throws Exception {
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, KEY,ivParameterSpec); // or Cipher.DECRYPT_MODE
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedText,SecretKey KEY)
            throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(encryptedText);
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, KEY,ivParameterSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
    public static SecretKey ConvertToSecretKey(String str){
        byte[] decodedKey = Base64.getDecoder().decode(str);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
    public static String ConvertToString(SecretKey secretKey){
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }





}
