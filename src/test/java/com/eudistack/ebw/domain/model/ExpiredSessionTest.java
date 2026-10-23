package com.eudistack.ebw.domain.model;

import com.eudistack.ebw.domain.model.exception.SessionExpiredException.Reason;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link ExpiredSession}: which session limit was reached. */
class ExpiredSessionTest {

    private static final Instant STARTED_AT = Instant.parse("2026-10-15T08:00:00Z");
    private static final Duration MAX_DURATION = Duration.ofHours(8);

    private static ExpiredSession lastTokenExpiringAt(Instant lastExpiresAt) {
        return new ExpiredSession(UUID.randomUUID(), UUID.randomUUID(), STARTED_AT, lastExpiresAt);
    }

    @Test
    void reason_lastTokenExpiredBeforeTheMaximumDuration_isIdleTimeout() {
        // Arrange
        var session = lastTokenExpiringAt(STARTED_AT.plus(Duration.ofHours(2)));

        // Act + Assert
        assertThat(session.reason(MAX_DURATION)).isEqualTo(Reason.IDLE_TIMEOUT);
    }

    @Test
    void reason_lastTokenCappedAtTheMaximumDuration_isMaxDuration() {
        // Arrange
        var session = lastTokenExpiringAt(STARTED_AT.plus(MAX_DURATION));

        // Act + Assert
        assertThat(session.reason(MAX_DURATION)).isEqualTo(Reason.MAX_DURATION);
    }

    @Test
    void reason_maximumDurationShortenedAfterTheTokenWasIssued_isMaxDuration() {
        // Arrange
        var session = lastTokenExpiringAt(STARTED_AT.plus(MAX_DURATION));

        // Act + Assert
        assertThat(session.reason(Duration.ofHours(4))).isEqualTo(Reason.MAX_DURATION);
    }

    @Test
    void reasonCode_eachReason_isTheLowerCaseAuditValue() {
        // Act + Assert
        assertThat(Reason.IDLE_TIMEOUT.code()).isEqualTo("idle_timeout");
        assertThat(Reason.MAX_DURATION.code()).isEqualTo("max_duration");
    }
}
