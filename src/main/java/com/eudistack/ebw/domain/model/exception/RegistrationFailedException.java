package com.eudistack.ebw.domain.model.exception;

/** The ceremony is unknown, expired or used, or the registration response does not verify. */
public class RegistrationFailedException extends RuntimeException {

    public RegistrationFailedException(String reason) {
        super(reason);
    }
}
