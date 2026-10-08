package com.eudistack.ebw.infrastructure.adapter.crypto;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link BcryptHashProvider} — BCrypt for OTP codes, hex SHA-256 for token lookups and audit hashes.
 */
class BcryptHashProviderTest {

    private final BcryptHashProvider hashProvider = new BcryptHashProvider();

    @Test
    void hash_rawValue_producesABcryptHashThatVerifies() {
        // Act
        var result = hashProvider.hash("123456")
                .flatMap(hash -> hashProvider.verify("123456", hash).map(matches -> hash + "|" + matches));

        // Assert
        StepVerifier.create(result)
                .assertNext(value -> {
                    assertThat(value).startsWith("$2a$10$");
                    assertThat(value).endsWith("|true");
                })
                .verifyComplete();
    }

    @Test
    void verify_wrongValue_returnsFalse() {
        // Act
        var result = hashProvider.hash("123456").flatMap(hash -> hashProvider.verify("654321", hash));

        // Assert
        StepVerifier.create(result).expectNext(false).verifyComplete();
    }

    @Test
    void sha256_knownInput_returnsLowercaseHexDigest() {
        // Act
        var digest = hashProvider.sha256("abc");

        // Assert
        assertThat(digest).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
