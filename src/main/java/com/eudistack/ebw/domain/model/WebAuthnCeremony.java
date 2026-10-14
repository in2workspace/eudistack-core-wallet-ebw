package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Challenge issued by the service for one WebAuthn ceremony. Valid {@link #TTL} and single
 * use: the registration or authentication consumes it before verifying anything.
 *
 * @param userId account the ceremony is bound to; {@code null} for a sign-in without ticket
 */
public record WebAuthnCeremony(
        UUID id,
        CeremonyType type,
        byte[] challenge,
        UUID userId,
        Instant expiresAt,
        Instant consumedAt,
        Instant createdAt
) {

    public static final Duration TTL = Duration.ofMinutes(5);
    public static final int CHALLENGE_LENGTH = 32;

    public static WebAuthnCeremony start(CeremonyType type, byte[] challenge, UUID userId) {
        if (challenge == null || challenge.length != CHALLENGE_LENGTH) {
            throw new IllegalArgumentException("Challenge must be " + CHALLENGE_LENGTH + " bytes");
        }
        var now = Instant.now();
        return new WebAuthnCeremony(UUID.randomUUID(), type, challenge.clone(), userId, now.plus(TTL), null, now);
    }
}
