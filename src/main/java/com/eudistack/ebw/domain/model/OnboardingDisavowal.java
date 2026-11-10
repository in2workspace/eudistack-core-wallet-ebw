package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * "It was not me" token of the email sent when a passkey is registered with an onboarding
 * ticket (design §2.6). Single use, valid {@link #TTL}. Only its SHA-256 is stored.
 *
 * @param passkeyId      passkey registered with the ticket; {@code null} if the holder removed it
 * @param requestedBy    system that requested the onboarding ticket
 * @param registeredAt   when the passkey was registered
 * @param accountCreated {@code true} if the ticket created the account, {@code false} if the
 *                       account already existed without passkeys (EUD-315 decision P17)
 */
public record OnboardingDisavowal(
        UUID id,
        String tokenHash,
        UUID userId,
        UUID passkeyId,
        String requestedBy,
        Instant registeredAt,
        boolean accountCreated,
        Instant expiresAt,
        Instant consumedAt,
        Instant createdAt
) {

    public static final Duration TTL = Duration.ofDays(7);

    /**
     * Row created with the account, before the new-account email: the token and its expiry are set
     * when the email is sent (EUD-315 decision P6, provisional).
     */
    public static OnboardingDisavowal pending(UUID userId, UUID passkeyId, String requestedBy, Instant registeredAt,
                                              boolean accountCreated) {
        return new OnboardingDisavowal(UUID.randomUUID(), null, userId, passkeyId, requestedBy, registeredAt,
                accountCreated, null, null, Instant.now());
    }

    public static OnboardingDisavowal issue(String tokenHash, UUID userId, UUID passkeyId, String requestedBy,
                                            Instant registeredAt, boolean accountCreated) {
        var now = Instant.now();
        return new OnboardingDisavowal(UUID.randomUUID(), tokenHash, userId, passkeyId, requestedBy, registeredAt,
                accountCreated, registeredAt.plus(TTL), null, now);
    }
}
