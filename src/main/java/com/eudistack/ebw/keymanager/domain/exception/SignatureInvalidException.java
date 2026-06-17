package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when the client's signed assertion fails structural or cryptographic validation
 * during the hybrid (Passkey PRF) submit step.
 *
 * <p>In US-01 (EUDISTACK-533) only the skeleton is present; the exception is declared here
 * so the exception handler and tests can reference it. Full cryptographic validation is
 * implemented in US-04 (EUDISTACK-536).</p>
 *
 * <p>Spec: EUDISTACK-533 ES-03, architecture.md §8.3 (error catalogue).</p>
 */
public class SignatureInvalidException extends RuntimeException {

    public SignatureInvalidException() {
        super("Signed assertion is structurally invalid or does not match the holder key.");
    }

    public SignatureInvalidException(String detail) {
        super(detail);
    }
}
