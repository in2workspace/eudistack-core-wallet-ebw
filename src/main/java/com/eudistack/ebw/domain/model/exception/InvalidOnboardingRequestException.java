package com.eudistack.ebw.domain.model.exception;

/** An onboarding ticket request with a value the contract does not accept (for instance an offer by value). */
public class InvalidOnboardingRequestException extends RuntimeException {

    public InvalidOnboardingRequestException(String message) {
        super(message);
    }
}
