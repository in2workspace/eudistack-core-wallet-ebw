package com.eudistack.ebw.infrastructure.adapter.crypto;

import com.eudistack.ebw.infrastructure.adapter.properties.EncryptionProperties;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Aes256GcmEncryptorTest {

    private static final String VALID_KEY = Base64.getEncoder().encodeToString(new byte[32]);

    @Test
    void encryptDecrypt_roundTrip() {
        var encryptor = createEncryptor(VALID_KEY);
        var plaintext = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test-credential-raw-content";

        var encrypted = encryptor.encrypt(plaintext);
        assertThat(encrypted).isNotEqualTo(plaintext);

        var decrypted = encryptor.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void encrypt_producesDifferentCiphertextEachTime() {
        var encryptor = createEncryptor(VALID_KEY);
        var plaintext = "same-plaintext";

        var encrypted1 = encryptor.encrypt(plaintext);
        var encrypted2 = encryptor.encrypt(plaintext);

        assertThat(encrypted1).isNotEqualTo(encrypted2); // Random IV each time
    }

    @Test
    void decrypt_withWrongKey_throwsException() {
        var encryptor1 = createEncryptor(VALID_KEY);
        var encrypted = encryptor1.encrypt("secret");

        var differentKey = Base64.getEncoder().encodeToString(new byte[]{
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
        });
        var encryptor2 = createEncryptor(differentKey);

        assertThatThrownBy(() -> encryptor2.decrypt(encrypted))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Decryption failed");
    }

    @Test
    void init_invalidKeyLength_throwsException() {
        var shortKey = Base64.getEncoder().encodeToString(new byte[16]); // 16 bytes, not 32
        assertThatThrownBy(() -> createEncryptor(shortKey))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void init_noKeyConfigured_throwsException() {
        assertThatThrownBy(() -> createEncryptor(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not configured");
    }

    private Aes256GcmEncryptor createEncryptor(String key) {
        var props = new EncryptionProperties(null, key);
        var encryptor = new Aes256GcmEncryptor(props);
        encryptor.init();
        return encryptor;
    }
}
