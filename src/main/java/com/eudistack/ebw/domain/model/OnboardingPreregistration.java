package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * Pre-registration created by an authorized system with an onboarding ticket (design §2.6,
 * AD-7). Holds the email and the credential offer until the first passkey is registered or it
 * expires; it never is an account. Only the SHA-256 of the ticket is stored (AD-8).
 *
 * @param credentialOffer    offer by reference sent by the system, {@code null} if none
 * @param requestedBy        identifier of the system that requested the ticket
 * @param webauthnUserHandle user handle of the future account, set when a ticket of an email
 *                           without account is redeemed. PROVISIONAL (EUD-315 decision P2,
 *                           pending Tech Lead): design §5 does not say where it lives.
 * @param redeemedAt         when the ticket was redeemed, {@code null} if not yet
 */
public record OnboardingPreregistration(
        UUID id,
        String tokenHash,
        String email,
        String credentialOffer,
        String requestedBy,
        byte[] webauthnUserHandle,
        Instant expiresAt,
        Instant redeemedAt,
        Instant createdAt
) {

    public static OnboardingPreregistration create(String tokenHash, String email, String credentialOffer,
                                                   String requestedBy, Duration ttl) {
        var now = Instant.now();
        return new OnboardingPreregistration(UUID.randomUUID(), tokenHash, email, credentialOffer, requestedBy, null,
                now.plus(ttl), null, now);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof OnboardingPreregistration(var otherId, var otherTokenHash, var otherEmail,
                                                          var otherOffer, var otherRequestedBy, var otherHandle,
                                                          var otherExpiresAt, var otherRedeemedAt,
                                                          var otherCreatedAt)
                && Objects.equals(id, otherId)
                && Objects.equals(tokenHash, otherTokenHash)
                && Objects.equals(email, otherEmail)
                && Objects.equals(credentialOffer, otherOffer)
                && Objects.equals(requestedBy, otherRequestedBy)
                && Arrays.equals(webauthnUserHandle, otherHandle)
                && Objects.equals(expiresAt, otherExpiresAt)
                && Objects.equals(redeemedAt, otherRedeemedAt)
                && Objects.equals(createdAt, otherCreatedAt);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(id, tokenHash, email, credentialOffer, requestedBy, expiresAt, redeemedAt, createdAt)
                + Arrays.hashCode(webauthnUserHandle);
    }

    /** Never prints the email nor the offer: they are personal data. */
    @Override
    public String toString() {
        return "OnboardingPreregistration[id=" + id + ", email=[redacted], credentialOffer=[redacted], requestedBy="
                + requestedBy + ", expiresAt=" + expiresAt + ", redeemedAt=" + redeemedAt + "]";
    }
}
