package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when the hybrid onboarding commit payload is structurally invalid.
 *
 * <p>Conditions: {@code wrapped_blob} decodes to less than 48 bytes, {@code iv} is not
 * 12 bytes, or {@code cnf_jwk} contains the private-key parameter {@code "d"}.</p>
 *
 * <p>Maps to HTTP 400 {@code invalid_request} in
 * {@code HybridOnboardingExceptionHandler}. The message MUST NOT include key material,
 * PRF salt, or wrapped blob content.</p>
 *
 * <p>Spec: EUDISTACK-534 ES-01; architecture.md §8.3.</p>
 */
public class InvalidCommitException extends RuntimeException {

    public InvalidCommitException(String reason) {
        super(reason);
    }
}