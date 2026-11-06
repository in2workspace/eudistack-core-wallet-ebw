package com.eudistack.ebw.domain.model;

/**
 * Outcome of redeeming an onboarding ticket (design §2.6, EUD-8 contract).
 *
 * @param hasPasskeys        the account of the email already has passkeys: no registration ticket,
 *                           the user signs in
 * @param sessionOfAccount   the request carried an active session of the ticket's account
 * @param registrationTicket raw registration ticket, only when the email has no account or one
 *                           without passkeys; {@code null} otherwise
 * @param expiresIn          seconds the registration ticket lives; {@code null} without it
 * @param credentialOffer    offer sent by the system with the ticket, {@code null} if none
 */
public record OnboardingTicketRedemption(
        boolean hasPasskeys,
        boolean sessionOfAccount,
        String registrationTicket,
        Long expiresIn,
        String credentialOffer
) {

    /** Never prints the registration ticket nor the offer. */
    @Override
    public String toString() {
        return "OnboardingTicketRedemption[hasPasskeys=" + hasPasskeys + ", sessionOfAccount=" + sessionOfAccount
                + ", registrationTicket=" + (registrationTicket == null ? "null" : "[redacted]")
                + ", expiresIn=" + expiresIn + ", credentialOffer=[redacted]]";
    }
}
