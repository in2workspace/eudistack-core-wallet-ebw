package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
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


    @Override
    public boolean equals(Object other) {
        return other instanceof WebAuthnCeremony that
                && Objects.equals(id, that.id)
                && type == that.type
                && Arrays.equals(challenge, that.challenge)
                && Objects.equals(userId, that.userId)
                && Objects.equals(expiresAt, that.expiresAt)
                && Objects.equals(consumedAt, that.consumedAt)
                && Objects.equals(createdAt, that.createdAt);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(id, type, userId, expiresAt, consumedAt, createdAt) + Arrays.hashCode(challenge);
    }

    @Override
    public String toString() {
        return "WebAuthnCeremony[id=" + id + ", type=" + type + ", challenge=[redacted], userId=" + userId
                + ", expiresAt=" + expiresAt + ", consumedAt=" + consumedAt + ", createdAt=" + createdAt + "]";
    }
}
