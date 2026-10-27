package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Proof of email possession returned by {@code verify-email}, or by the redemption of an
 * onboarding ticket. Single use: consumed when a session is opened with it. Only the SHA-256 of
 * the raw ticket is stored.
 *
 * @param userId            account of the ticket; {@code null} for an onboarding ticket of an
 *                          email without account (the account is created with the passkey)
 * @param preregistrationId pre-registration of the onboarding ticket it comes from, if any. At
 *                          least one of {@code userId} and {@code preregistrationId} is set.
 */
public record RegistrationTicket(
        UUID id,
        UUID userId,
        UUID preregistrationId,
        String tokenHash,
        Instant expiresAt,
        Instant consumedAt,
        Instant createdAt
) {

    public static final Duration TTL = Duration.ofMinutes(5);

    /** Ticket of an email verification: the account, valid {@link #TTL}. */
    public static RegistrationTicket issue(UUID userId, String tokenHash) {
        var now = Instant.now();
        return new RegistrationTicket(UUID.randomUUID(), userId, null, tokenHash, now.plus(TTL), null, now);
    }

    /** Ticket of a redeemed onboarding ticket: expires with its pre-registration. */
    public static RegistrationTicket issueForPreregistration(UUID userId, UUID preregistrationId, String tokenHash,
                                                             Instant expiresAt) {
        return new RegistrationTicket(UUID.randomUUID(), userId, preregistrationId, tokenHash, expiresAt, null,
                Instant.now());
    }
}
