package com.eudistack.ebw.infrastructure.adapter.crypto;

import com.eudistack.ebw.infrastructure.adapter.properties.EncryptionProperties;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.stream.IntStream;

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

    /**
     * After hoisting {@code SecureRandom} to a {@code static final} field (EUDI-040 review W1)
     * the encryptor must still draw a fresh IV for every {@code encrypt} call. This test
     * encrypts the same plaintext many times and asserts that both the resulting ciphertexts
     * AND the extracted 12-byte IV prefixes are pairwise distinct — which is the actual
     * observable property the hoist must preserve.
     */
    @Test
    void encrypt_producesUniqueIvsAcrossManyCalls() {
        var encryptor = createEncryptor(VALID_KEY);
        var plaintext = "same-plaintext-many-times";
        var iterations = 50;

        var ciphertexts = new HashSet<String>();
        var ivs = new HashSet<String>();

        IntStream.range(0, iterations).forEach(i -> {
            var encoded = encryptor.encrypt(plaintext);
            ciphertexts.add(encoded);

            // Encrypted payload layout produced by Aes256GcmEncryptor.encrypt:
            //   Base64( iv[0..12) || ciphertext+tag[12..) )
            // The IV is the first 12 bytes of the decoded payload.
            var decoded = Base64.getDecoder().decode(encoded);
            var iv = Arrays.copyOfRange(decoded, 0, 12);
            ivs.add(Base64.getEncoder().encodeToString(iv));
        });

        assertThat(ciphertexts).as("all ciphertexts must differ").hasSize(iterations);
        assertThat(ivs).as("all IVs must be distinct").hasSize(iterations);
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
