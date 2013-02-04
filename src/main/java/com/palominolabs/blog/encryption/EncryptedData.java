package com.palominolabs.blog.encryption;

final class EncryptedData {
    private final byte[] ciphertext;
    private final byte[] iv;
    private final byte[] mac;

    public EncryptedData(byte[] ciphertext, byte[] iv, byte[] mac) {
        this.ciphertext = ciphertext;
        this.iv = iv;
        this.mac = mac;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getMac() {
        return mac;
    }
}
