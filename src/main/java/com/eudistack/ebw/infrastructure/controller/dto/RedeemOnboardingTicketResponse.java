package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.OnboardingTicketRedemption;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Answer of {@code POST /auth/onboarding-tickets/redeem} (EUD-8 contract). The registration
 * ticket, its lifetime and the offer are left out when absent.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record RedeemOnboardingTicketResponse(
        boolean hasPasskeys,
        boolean sessionOfAccount,
        String registrationTicket,
        Long expiresIn,
        String credentialOffer
) {

    public static RedeemOnboardingTicketResponse from(OnboardingTicketRedemption redemption) {
        return new RedeemOnboardingTicketResponse(redemption.hasPasskeys(), redemption.sessionOfAccount(),
                redemption.registrationTicket(), redemption.expiresIn(), redemption.credentialOffer());
    }

    @Override
    public String toString() {
        return "RedeemOnboardingTicketResponse[hasPasskeys=" + hasPasskeys + ", sessionOfAccount="
                + sessionOfAccount + ", registrationTicket=" + (registrationTicket == null ? "null" : "[redacted]")
                + ", expiresIn=" + expiresIn + ", credentialOffer=[redacted]]";
    }
}
