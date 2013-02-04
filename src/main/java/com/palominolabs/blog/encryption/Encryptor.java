package com.palominolabs.blog.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

final class Encryptor {
    // Sizes appropriate AES: 128 bit IV, 256 bit key
    public static final int IV_SIZE = 16;
    public static final int KEY_SIZE = 32;

    private final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private final String MAC_ALGORITHM = "HmacSHA512";

    private final byte[] aesKey;
    private final byte[] macKey;

    private Cipher cipher;
    private Mac mac;
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Create a new Encryptor, providing keys
     *
     * @param aesKey The 32 byte AES key
     * @param macKey The 32 byte SHA-512 MAC key
     */
    public Encryptor(byte[] aesKey, byte[] macKey) {
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            mac = Mac.getInstance(MAC_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw die("Your system doesn't know " + CIPHER_ALGORITHM.substring(0, CIPHER_ALGORITHM.indexOf("/")), e);
        } catch (NoSuchPaddingException e) {
            throw die("Your system doesn't know " + CIPHER_ALGORITHM.substring(CIPHER_ALGORITHM.lastIndexOf("/")), e);
        }

        this.aesKey = aesKey;
        this.macKey = macKey;
    }

    /**
     * Encrypt a byte array
     *
     * @param plaintext The plaintext to encrypt
     * @return An EncryptedData object encapsulating the ciphertext, IV, and MAC
     */
    public EncryptedData encrypt(byte[] plaintext) {
        byte[] ciphertext;
        byte[] iv = generateIv();

        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            ciphertext = cipher.doFinal(plaintext);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw die("Error while encrypting", e);
        }

        return new EncryptedData(ciphertext, iv, computeMac(iv, ciphertext));
    }

    /**
     * Decrypt a byte array.  Fails if the provided MAC does not match
     *
     * @param encrypted An EncryptedData object encapsulating the ciphertext, IV, and MAC
     * @return The plaintext
     */
    public byte[] decrypt(EncryptedData encrypted) {

        try {
            // Compute the MAC and check against the given one
            if (!MessageDigest.isEqual(encrypted.getMac(), computeMac(encrypted.getIv(), encrypted.getCiphertext()))) {
                throw die("MAC mismatch");
            }

            SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(encrypted.getIv());
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(encrypted.getCiphertext());
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw die("Error while decrypting", e);
        }
    }

    /**
     * Compute MAC for a byte array
     *
     * @param iv         iv
     * @param ciphertext The ciphertext to MAC
     * @return MAC of the given byte array
     */
    private byte[] computeMac(byte[] iv, byte[] ciphertext) {

        ByteBuffer buf = ByteBuffer.allocate(iv.length + ciphertext.length);
        buf.put(iv).put(ciphertext);
        try {
            mac.init(new SecretKeySpec(macKey, MAC_ALGORITHM));
            return mac.doFinal(buf.array());
        } catch (InvalidKeyException e) {
            throw die("Error while decrypting", e);
        }
    }

    /**
     * Generate a random initialization vector
     *
     * @return An array of random bytes
     */
    private byte[] generateIv() {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private RuntimeException die(String message) {
        throw new RuntimeException(message);
    }

    private RuntimeException die(String message, Exception e) {
        return new RuntimeException(message, e);
    }
}