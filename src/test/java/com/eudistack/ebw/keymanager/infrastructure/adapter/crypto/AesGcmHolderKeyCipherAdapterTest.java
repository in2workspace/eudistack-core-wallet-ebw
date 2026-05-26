package com.eudistack.ebw.keymanager.infrastructure.adapter.crypto;

import com.eudistack.ebw.infrastructure.adapter.properties.EncryptionProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AesGcmHolderKeyCipherAdapterTest {

    // Fixed 32-byte AES-256 key for deterministic tests
    private static final byte[] KEY_32 = new byte[32];
    private static final String KEY_32_B64 = Base64.getEncoder().encodeToString(KEY_32);

    private AesGcmHolderKeyCipherAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = newAdapter(KEY_32_B64);
    }

    private AesGcmHolderKeyCipherAdapter newAdapter(String base64Key) {
        var props = new EncryptionProperties(null, base64Key);
        var a = new AesGcmHolderKeyCipherAdapter(props);
        a.init(); // package-private @PostConstruct, callable from same package
        return a;
    }

    @Test
    void encrypt_decrypt_roundtrip_returnsOriginalPlaintext() {
        byte[] plaintext = "private-key-bytes".getBytes();
        byte[] encrypted = adapter.encrypt(plaintext, "tenant-1");
        byte[] decrypted = adapter.decrypt(encrypted, "tenant-1");

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void encrypt_producesUniqueNoncePerCall_ciphertextsDiffer() {
        byte[] plaintext = "same-plaintext".getBytes();
        byte[] first = adapter.encrypt(plaintext, "tenant-1");
        byte[] second = adapter.encrypt(plaintext, "tenant-1");

        assertThat(first).as("each encrypt call must produce a unique nonce, so ciphertexts differ")
                .isNotEqualTo(second);
    }

    @Test
    void decrypt_withWrongTenantId_throwsIllegalStateException() {
        byte[] plaintext = "private-key-bytes".getBytes();
        byte[] encrypted = adapter.encrypt(plaintext, "tenant-1");

        assertThatThrownBy(() -> adapter.decrypt(encrypted, "tenant-2"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Decryption failed");
    }

    @Test
    void decrypt_withTruncatedPayload_throwsIllegalStateException() {
        byte[] tooShort = new byte[5]; // shorter than NONCE_LENGTH=12

        assertThatThrownBy(() -> adapter.decrypt(tooShort, "tenant-1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("payload too short");
    }

    @Test
    void decrypt_withNullPayload_throwsIllegalStateException() {
        assertThatThrownBy(() -> adapter.decrypt(null, "tenant-1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("payload too short");
    }

    @Test
    void isOperational_returnsTrue_whenKeyIsValid() {
        assertThat(adapter.isOperational()).isTrue();
    }

    @Test
    void init_throwsIllegalStateException_whenKeyIsNot32Bytes() {
        byte[] shortKey = new byte[16];
        String shortKeyB64 = Base64.getEncoder().encodeToString(shortKey);
        var props = new EncryptionProperties(null, shortKeyB64);
        var a = new AesGcmHolderKeyCipherAdapter(props);

        assertThatThrownBy(a::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("AES-256 key must be 32 bytes");
    }
}