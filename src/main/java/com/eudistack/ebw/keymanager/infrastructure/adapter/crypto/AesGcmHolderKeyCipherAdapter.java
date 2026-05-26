package com.eudistack.ebw.keymanager.infrastructure.adapter.crypto;

import com.eudistack.ebw.infrastructure.adapter.properties.EncryptionProperties;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyCipherPort;
import jakarta.annotation.PostConstruct;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

public class AesGcmHolderKeyCipherAdapter implements HolderKeyCipherPort {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int NONCE_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final EncryptionProperties properties;
    private SecretKeySpec secretKey;

    public AesGcmHolderKeyCipherAdapter(EncryptionProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void init() {
        byte[] keyBytes = loadKey();
        if (keyBytes.length != 32) {
            throw new IllegalStateException("AES-256 key must be 32 bytes, got " + keyBytes.length);
        }
        this.secretKey = new SecretKeySpec(keyBytes, "AES");
    }

    @Override
    public byte[] encrypt(byte[] plaintext, String tenantId) {
        try {
            var nonce = new byte[NONCE_LENGTH];
            SECURE_RANDOM.nextBytes(nonce);

            var cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(tenantId.getBytes(StandardCharsets.UTF_8));
            var ciphertext = cipher.doFinal(plaintext);

            var result = new byte[NONCE_LENGTH + ciphertext.length];
            System.arraycopy(nonce, 0, result, 0, NONCE_LENGTH);
            System.arraycopy(ciphertext, 0, result, NONCE_LENGTH, ciphertext.length);
            return result;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String tenantId) {
        if (ciphertext == null || ciphertext.length <= NONCE_LENGTH) {
            throw new IllegalStateException("Decryption failed: payload too short");
        }
        try {
            var nonce = new byte[NONCE_LENGTH];
            System.arraycopy(ciphertext, 0, nonce, 0, NONCE_LENGTH);

            var cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(tenantId.getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(ciphertext, NONCE_LENGTH, ciphertext.length - NONCE_LENGTH);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }

    @Override
    public boolean isOperational() {
        try {
            var probe = "probe".getBytes(StandardCharsets.UTF_8);
            var encrypted = encrypt(probe, "health-check");
            var decrypted = decrypt(encrypted, "health-check");
            return java.util.Arrays.equals(probe, decrypted);
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] loadKey() {
        if (properties.key() != null && !properties.key().isBlank()) {
            return Base64.getDecoder().decode(properties.key());
        }
        if (properties.keyPath() != null && !properties.keyPath().isBlank()) {
            try {
                var content = Files.readString(Path.of(properties.keyPath())).trim();
                return Base64.getDecoder().decode(content);
            } catch (IOException e) {
                throw new IllegalStateException("Cannot read encryption key from " + properties.keyPath(), e);
            }
        }
        throw new IllegalStateException(
                "Encryption key not configured. Set ebw.encryption.key or ebw.encryption.key-path");
    }
}