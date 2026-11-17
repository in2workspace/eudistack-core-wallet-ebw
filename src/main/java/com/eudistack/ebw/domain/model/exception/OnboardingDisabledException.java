package com.eudistack.ebw.domain.model.exception;

/** The tenant has not enabled onboarding tickets ({@code ebw.onboarding.enabled}). */
public class OnboardingDisabledException extends RuntimeException {

    public OnboardingDisabledException() {
        super("Onboarding tickets are not enabled in this tenant");
    }
}
