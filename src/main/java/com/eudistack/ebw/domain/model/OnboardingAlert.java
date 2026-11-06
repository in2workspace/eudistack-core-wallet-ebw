package com.eudistack.ebw.domain.model;

import java.time.Instant;

/**
 * Content of the alert to the tenant's security contact when an onboarding is disavowed (design
 * §2.6, FR-32): the holder's email masked, when the account was created and the system that
 * requested the ticket.
 *
 * @param maskedEmail  first letter and domain of the holder's email ({@code a***@example.org})
 * @param registeredAt when the account was created with the ticket
 * @param requestedBy  system that requested the onboarding ticket
 */
public record OnboardingAlert(String maskedEmail, Instant registeredAt, String requestedBy) {

    /** Keeps the first letter and the domain: the tenant can find the case without the full email. */
    public static String mask(String email) {
        if (email == null || email.isEmpty()) {
            return "***";
        }
        var at = email.lastIndexOf('@');
        return at <= 0 ? email.charAt(0) + "***" : email.charAt(0) + "***" + email.substring(at);
    }
}
