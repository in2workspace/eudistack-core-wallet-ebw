package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Proof of email possession returned by {@code verify-email}. Single account, valid
 * {@link #TTL}, single use: consumed when a session is opened with it. Only the SHA-256 of
 * the raw ticket is stored.
 */
public record RegistrationTicket(
        UUID id,
        UUID userId,
        String tokenHash,
        Instant expiresAt,
        Instant consumedAt,
        Instant createdAt
) {

    public static final Duration TTL = Duration.ofMinutes(5);

    public static RegistrationTicket issue(UUID userId, String tokenHash) {
        var now = Instant.now();
        return new RegistrationTicket(UUID.randomUUID(), userId, tokenHash, now.plus(TTL), null, now);
    }
}
