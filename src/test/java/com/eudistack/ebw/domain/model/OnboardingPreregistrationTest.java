package com.eudistack.ebw.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link OnboardingPreregistration}. */
class OnboardingPreregistrationTest {

    private static final UUID ID = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-11-09T10:00:00Z");

    private static OnboardingPreregistration withHandle(byte[] handle) {
        return new OnboardingPreregistration(ID, "hash", "user@example.com", "offer", "verifier", handle,
                NOW.plusSeconds(3600), null, NOW);
    }

    @Test
    void create_setsTheExpiryFromTheTtlAndNoHandleNorRedemption() {
        // Act
        var preregistration = OnboardingPreregistration.create("hash", "user@example.com", null, "verifier",
                Duration.ofHours(2));

        // Assert
        assertThat(preregistration.id()).isNotNull();
        assertThat(preregistration.webauthnUserHandle()).isNull();
        assertThat(preregistration.redeemedAt()).isNull();
        assertThat(Duration.between(preregistration.createdAt(), preregistration.expiresAt()))
                .isEqualTo(Duration.ofHours(2));
    }

    @Test
    void equals_sameHandleContent_isEqualWithTheSameHashCode() {
        // Arrange
        var one = withHandle(new byte[]{1, 2, 3});
        var other = withHandle(new byte[]{1, 2, 3});

        // Act & Assert
        assertThat(one).isEqualTo(other).hasSameHashCodeAs(other);
    }

    @Test
    void equals_differentHandleContent_isNotEqual() {
        // Act & Assert
        assertThat(withHandle(new byte[]{1, 2, 3})).isNotEqualTo(withHandle(new byte[]{9}));
    }

    @Test
    void equals_otherType_isNotEqual() {
        // Act & Assert
        assertThat(withHandle(null)).isNotEqualTo("not a preregistration");
    }

    @Test
    void toString_neverPrintsTheEmailNorTheOffer() {
        // Act
        var text = withHandle(null).toString();

        // Assert
        assertThat(text).contains(ID.toString(), "verifier").doesNotContain("user@example.com", "offer=offer");
    }
}
