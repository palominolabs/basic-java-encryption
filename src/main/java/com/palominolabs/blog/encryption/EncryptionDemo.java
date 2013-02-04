package com.palominolabs.blog.encryption;

import com.google.common.base.Charsets;

import java.security.NoSuchAlgorithmException;

import static com.palominolabs.blog.encryption.Util.readInput;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;
import static org.apache.commons.codec.binary.Hex.encodeHexString;

final class EncryptionDemo {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        pl("Generate random Base64 data with the following shell command:");
        pl("    dd if=/dev/random bs=1 count=32 | base64");
        pl("The 32 is the number of bytes to generate (256 bits). Use 16 if a 128 bit key is desired.");
        pl("Make sure to use separate keys for encryption and MAC.");
        pl("");

        byte[] aesKey = decodeBase64(readInput("Provide a Base64 AES key:"));
        byte[] macKey = decodeBase64(readInput("Provide a Base64 MAC key:"));

        byte[] plaintext = readInput("Plaintext:").getBytes(Charsets.UTF_8);
        if (plaintext == null) {
            pl("Please provide input terminated by a newline");
            System.exit(1);
        }

        // Initialize the Encryptor with the given keys
        Encryptor encryptor = new Encryptor(aesKey, macKey);

        // Encrypt and generate the HMAC of the ciphertext
        EncryptedData encrypted = encryptor.encrypt(plaintext);

        pl("");
        pl("IV: " + encodeBase64String(encrypted.getIv()));
        pl("Ciphertext: " + encodeBase64String(encrypted.getCiphertext()));
        pl("MAC: " + encodeBase64String(encrypted.getMac()));
        pl("Use the above parameters with DecryptionDemo to see that you get your plaintext back out.");
        pl("");
        pl("Also, you can check interoperability by decrypting with OpenSSL");
        pl("Note that OpenSSL wants hex instead of base64, which is why the key, IV, and MAC look different:");
        pl("    echo '" + encodeBase64String(encrypted.getCiphertext()) + "' | base64 -D | \\");
        pl("    openssl enc -aes-256-cbc -d -K " + encodeHexString(aesKey) + " -iv " +
            encodeHexString(encrypted.getIv()));
    }

    private static void pl(String s) {
        System.out.println(s);
    }
}