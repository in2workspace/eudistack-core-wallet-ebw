package com.eudistack.ebw.infrastructure.adapter.crypto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CsprngGenerator} — numeric OTPs of the requested length and random UUIDs.
 */
class CsprngGeneratorTest {

    private final CsprngGenerator generator = new CsprngGenerator();

    @Test
    void generateOtp_requestedLength_returnsOnlyDigitsOfThatLength() {
        // Act
        var otp = generator.generateOtp(6);

        // Assert
        assertThat(otp).hasSize(6).containsOnlyDigits();
    }

    @Test
    void generateOtp_zeroLength_returnsEmptyString() {
        // Act
        var otp = generator.generateOtp(0);

        // Assert
        assertThat(otp).isEmpty();
    }

    @Test
    void generateUuid_consecutiveCalls_returnDistinctVersion4Uuids() {
        // Act
        var first = generator.generateUuid();
        var second = generator.generateUuid();

        // Assert
        assertThat(first).isNotEqualTo(second);
        assertThat(first.version()).isEqualTo(4);
    }
}
