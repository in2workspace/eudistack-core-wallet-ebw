package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Session limits of a tenant: inactivity period (the refresh token expires that long after
 * it is issued) and maximum duration since the session was opened.
 */
public record SessionSettings(Duration idleTimeout, Duration maxDuration) {

    public static final Duration DEFAULT_IDLE_TIMEOUT = Duration.ofMinutes(5);
    public static final Duration DEFAULT_MAX_DURATION = Duration.ofHours(8);

    public SessionSettings {
        Objects.requireNonNull(idleTimeout, "idleTimeout");
        Objects.requireNonNull(maxDuration, "maxDuration");
        if (idleTimeout.isNegative() || idleTimeout.isZero() || maxDuration.isNegative() || maxDuration.isZero()) {
            throw new IllegalArgumentException("Session limits must be positive");
        }
    }

    public static SessionSettings defaults() {
        return new SessionSettings(DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_DURATION);
    }
}
