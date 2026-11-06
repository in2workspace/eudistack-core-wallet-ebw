package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * "It was not me" token of the new-account email of an account created with an onboarding
 * ticket (design §2.6). Single use, valid {@link #TTL}. Only its SHA-256 is stored.
 *
 * @param passkeyId    passkey registered with the ticket; {@code null} if the holder removed it
 * @param requestedBy  system that requested the onboarding ticket
 * @param registeredAt when the account was created
 */
public record OnboardingDisavowal(
        UUID id,
        String tokenHash,
        UUID userId,
        UUID passkeyId,
        String requestedBy,
        Instant registeredAt,
        Instant expiresAt,
        Instant consumedAt,
        Instant createdAt
) {

    public static final Duration TTL = Duration.ofDays(7);

    /**
     * Row created with the account, before the new-account email: the token and its expiry are set
     * when the email is sent (EUD-315 decision P6, provisional).
     */
    public static OnboardingDisavowal pending(UUID userId, UUID passkeyId, String requestedBy, Instant registeredAt) {
        return new OnboardingDisavowal(UUID.randomUUID(), null, userId, passkeyId, requestedBy, registeredAt, null,
                null, Instant.now());
    }

    public static OnboardingDisavowal issue(String tokenHash, UUID userId, UUID passkeyId, String requestedBy,
                                            Instant registeredAt) {
        var now = Instant.now();
        return new OnboardingDisavowal(UUID.randomUUID(), tokenHash, userId, passkeyId, requestedBy, registeredAt,
                registeredAt.plus(TTL), null, now);
    }
}
