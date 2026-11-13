package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/** Body of {@code POST /auth/onboarding-tickets/redeem} (EUD-8 contract): the 22-character ticket. */
public record RedeemOnboardingTicketRequest(
        @NotNull @Pattern(regexp = "^[A-Za-z0-9_-]{22}$") String ticket
) {

    @Override
    public String toString() {
        return "RedeemOnboardingTicketRequest[ticket=[redacted]]";
    }
}
