package com.eudistack.ebw.infrastructure.adapter.verifier;

/** The Verifier's keys could not be read and there is no copy of them: system tokens cannot be checked (503). */
public class VerifierUnavailableException extends RuntimeException {

    public VerifierUnavailableException(String message) {
        super(message);
    }

    public VerifierUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
