package com.palominolabs.blog.encryption;

import com.google.common.base.Charsets;
import org.junit.Before;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.SecureRandom;

import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public final class EncryptorTest {
    private final SecureRandom secureRandom = new SecureRandom();

    @Before
    public void setUp() {
    }

    @Test
    public void testEncryptDecrypt() {
        byte[] aesKey = new byte[Encryptor.KEY_SIZE];
        byte[] macKey = new byte[Encryptor.KEY_SIZE];
        secureRandom.nextBytes(aesKey);
        secureRandom.nextBytes(macKey);
        Encryptor encryptor = new Encryptor(aesKey, macKey);

        byte[] plaintext = new byte[1024];
        secureRandom.nextBytes(plaintext);

        EncryptedData encryptedData = encryptor.encrypt(plaintext);
        assertNotNull(encryptedData.getCiphertext());
        assertNotNull(encryptedData.getIv());
        assertNotNull(encryptedData.getMac());

        assertTrue(MessageDigest.isEqual(encryptor.decrypt(encryptedData), plaintext));
    }

    @Test
    public void testDecrypt() {
        byte[] plaintext = "Foobar.".getBytes(Charsets.UTF_8);
        byte[] aesKey = decodeBase64("Dz6haTBfKkaFfo92dCMZM4VXDiL2vafbkU3uAPOt6AU=");
        byte[] macKey = decodeBase64("TG1MLx8+1XEQ+YdIYEIcQvhQ9AZtc9jy9HRCKkVeVwQ=");

        byte[] iv = decodeBase64("kw6Vzdy2JNP9rK6KIUTUkQ==");
        byte[] ciphertext = decodeBase64("ox5eqRCiQ9X+YiU9zQrKvw==");
        byte[] mac = decodeBase64("2RzK5Xybx2oi15YvKywtX/2BszLzqYyVGNsHp0RTSOnDGB6jdFVIl/vCdkoJGxUoVB/8gFc4WEWthi0GVvlzJw==");

        Encryptor encryptor = new Encryptor(aesKey, macKey);
        assertTrue(MessageDigest.isEqual(encryptor.decrypt(new EncryptedData(ciphertext, iv, mac)), plaintext));
    }
}
