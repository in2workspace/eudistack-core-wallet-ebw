package com.eudistack.ebw.domain.model;

import java.time.Instant;

/**
 * Content of the alert to the tenant's security contact when an onboarding is disavowed (design
 * §2.6, FR-32): the holder's email masked and when the account was created. It does not name the
 * system that requested the ticket (EUD-315 decision P12): the audit trail keeps it.
 *
 * @param maskedEmail  first letter and domain of the holder's email ({@code a***@example.org})
 * @param registeredAt when the account was created with the ticket
 */
public record OnboardingAlert(String maskedEmail, Instant registeredAt) {

    /** Keeps the first letter and the domain: the tenant can find the case without the full email. */
    public static String mask(String email) {
        if (email == null || email.isEmpty()) {
            return "***";
        }
        var at = email.lastIndexOf('@');
        return at <= 0 ? email.charAt(0) + "***" : email.charAt(0) + "***" + email.substring(at);
    }
}
