package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when {@code prepareSign} or {@code getForHolder} cannot find a PRF salt row
 * for a given {@code (holderId, credentialId)} pair and the credential does not exist
 * in {@code hybrid_prf_salt} at all.
 *
 * <p>Maps to HTTP 404 with {@code error=wrap_handle_not_found} in
 * {@link com.eudistack.ebw.keymanager.infrastructure.adapter.http.HybridKeyManagerExceptionHandler}
 * (architecture.md §8.3).</p>
 *
 * <p>The exception message MUST NOT contain the {@code prf_salt} value or any
 * cryptographic material — it is only used for internal logging (NFR-S-537-01, AC-06).</p>
 *
 * <p>Spec: EUDISTACK-537 ES-02, ES-04; architecture.md §8.3.</p>
 */
public class PrfSaltNotFoundException extends RuntimeException {

    public PrfSaltNotFoundException(String credentialId) {
        super("PRF salt not found for credential: " + credentialId);
    }
}
