package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Body of {@code POST /onboarding-tickets} (EUD-8 contract). */
public record CreateOnboardingTicketRequest(
        @NotBlank @Email @Size(max = 254) String email,
        @Size(max = 2048) String credentialOffer,
        @Min(60) Integer expiresIn
) {

    @Override
    public String toString() {
        return "CreateOnboardingTicketRequest[email=[redacted], credentialOffer=[redacted], expiresIn=" + expiresIn
                + "]";
    }
}
