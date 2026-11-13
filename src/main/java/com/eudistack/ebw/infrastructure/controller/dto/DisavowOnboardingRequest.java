package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/** Body of {@code POST /auth/onboarding-tickets/disavowals} (EUD-8 contract): the "it was not me" token. */
public record DisavowOnboardingRequest(
        @NotNull @Pattern(regexp = "^[A-Za-z0-9_-]{22,64}$") String token
) {

    @Override
    public String toString() {
        return "DisavowOnboardingRequest[token=[redacted]]";
    }
}
