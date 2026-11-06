package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.OnboardingTicketIssued;

/** Answer of {@code POST /onboarding-tickets}: onboarding URL and its lifetime in seconds. */
public record OnboardingTicketResponse(String onboardingUrl, long expiresIn) {

    public static OnboardingTicketResponse from(OnboardingTicketIssued issued) {
        return new OnboardingTicketResponse(issued.onboardingUrl(), issued.expiresIn());
    }
}
