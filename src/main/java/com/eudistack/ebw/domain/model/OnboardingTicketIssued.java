package com.eudistack.ebw.domain.model;

/** Result of an onboarding ticket request: the onboarding URL ({@code https://<rpId>/t/<ticket>}) and its lifetime. */
public record OnboardingTicketIssued(String onboardingUrl, long expiresIn) {
}
