package com.palominolabs.blog.encryption;

import com.google.common.base.Charsets;

import java.security.NoSuchAlgorithmException;

import static com.palominolabs.blog.encryption.Util.readInput;
import static org.apache.commons.codec.binary.Base64.decodeBase64;

final class DecryptionDemo {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] aesKey = decodeBase64(readInput("Base64 AES key?"));
        byte[] macKey = decodeBase64(readInput("Base64 MAC key?"));
        byte[] iv = decodeBase64(readInput("Base64 IV?"));
        byte[] ciphertext = decodeBase64(readInput("Base64 Ciphertext?"));
        byte[] mac = decodeBase64(readInput("Base64 MAC?"));
        if (mac.length != 64 || iv.length != Encryptor.IV_SIZE) {
            System.err.println("Please double check your MAC and IV!");
            System.exit(1);
        }

        // Initialize the Encryptor with the given keys & IV
        Encryptor encryptor = new Encryptor(aesKey, macKey);

        // Decrypt, checking the HMAC of the ciphertext
        byte[] plaintext = encryptor.decrypt(new EncryptedData(ciphertext, iv, mac));

        System.out.println("Plaintext: " + new String(plaintext, Charsets.UTF_8));
    }
}