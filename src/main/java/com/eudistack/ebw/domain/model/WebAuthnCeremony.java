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
 * @param userId               account the ceremony is bound to; {@code null} for a sign-in without
 *                             ticket, or a registration for an account not created yet
 * @param registrationTicketId registration ticket that started a registration ceremony; {@code null}
 *                             for an authentication (EUD-315 decision P9, provisional)
 */
public record WebAuthnCeremony(
        UUID id,
        CeremonyType type,
        byte[] challenge,
        UUID userId,
        UUID registrationTicketId,
        Instant expiresAt,
        Instant consumedAt,
        Instant createdAt
) {

    public static final Duration TTL = Duration.ofMinutes(5);
    public static final int CHALLENGE_LENGTH = 32;

    public static WebAuthnCeremony start(CeremonyType type, byte[] challenge, UUID userId) {
        return start(type, challenge, userId, null);
    }

    /** Registration ceremony bound to the registration ticket that started it. */
    public static WebAuthnCeremony startRegistration(byte[] challenge, UUID userId, UUID registrationTicketId) {
        return start(CeremonyType.REGISTRATION, challenge, userId, registrationTicketId);
    }

    private static WebAuthnCeremony start(CeremonyType type, byte[] challenge, UUID userId, UUID registrationTicketId) {
        if (challenge == null || challenge.length != CHALLENGE_LENGTH) {
            throw new IllegalArgumentException("Challenge must be " + CHALLENGE_LENGTH + " bytes");
        }
        var now = Instant.now();
        return new WebAuthnCeremony(UUID.randomUUID(), type, challenge.clone(), userId, registrationTicketId,
                now.plus(TTL), null, now);
    }


    @Override
    public boolean equals(Object other) {
        return other instanceof WebAuthnCeremony(var otherId, var otherType, var otherChallenge, var otherUserId,
                                                 var otherTicketId, var otherExpiresAt, var otherConsumedAt,
                                                 var otherCreatedAt)
                && Objects.equals(id, otherId)
                && type == otherType
                && Arrays.equals(challenge, otherChallenge)
                && Objects.equals(userId, otherUserId)
                && Objects.equals(registrationTicketId, otherTicketId)
                && Objects.equals(expiresAt, otherExpiresAt)
                && Objects.equals(consumedAt, otherConsumedAt)
                && Objects.equals(createdAt, otherCreatedAt);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(id, type, userId, registrationTicketId, expiresAt, consumedAt, createdAt)
                + Arrays.hashCode(challenge);
    }

    @Override
    public String toString() {
        return "WebAuthnCeremony[id=" + id + ", type=" + type + ", challenge=[redacted], userId=" + userId
                + ", expiresAt=" + expiresAt + ", consumedAt=" + consumedAt + ", createdAt=" + createdAt + "]";
    }
}
