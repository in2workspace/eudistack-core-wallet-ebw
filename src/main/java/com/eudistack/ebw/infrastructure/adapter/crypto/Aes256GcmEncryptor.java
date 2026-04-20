package com.eudistack.ebw.infrastructure.adapter.crypto;

import com.eudistack.ebw.domain.spi.CredentialEncryptor;
import com.eudistack.ebw.infrastructure.adapter.properties.EncryptionProperties;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

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

@Component
public class Aes256GcmEncryptor implements CredentialEncryptor {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    // SecureRandom is thread-safe for nextBytes (internal state updates are serialized),
    // so a single shared instance is safe in a reactive context and avoids the per-call
    // self-seeding cost incurred by constructing a new SecureRandom on every encrypt().
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final EncryptionProperties properties;
    private SecretKeySpec secretKey;

    public Aes256GcmEncryptor(EncryptionProperties properties) {
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
    public String encrypt(String plaintext) {
        try {
            var iv = new byte[IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv);

            var cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            var ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            var result = new byte[IV_LENGTH + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, IV_LENGTH);
            System.arraycopy(ciphertext, 0, result, IV_LENGTH, ciphertext.length);

            return Base64.getEncoder().encodeToString(result);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    @Override
    public String decrypt(String encrypted) {
        try {
            var decoded = Base64.getDecoder().decode(encrypted);
            var iv = new byte[IV_LENGTH];
            System.arraycopy(decoded, 0, iv, 0, IV_LENGTH);

            var cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            var plaintext = cipher.doFinal(decoded, IV_LENGTH, decoded.length - IV_LENGTH);

            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decryption failed", e);
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
        throw new IllegalStateException("Encryption key not configured. Set ebw.encryption.key or ebw.encryption.key-path");
    }
}
