package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when a holder attempts to access a PRF salt that belongs to a different holder.
 *
 * <p>The composite primary key {@code (holder_id, credential_id)} in
 * {@code hybrid_prf_salt} means a successful SELECT for a given {@code holderId} can only
 * return a row owned by that holder. However, if {@code countByCredential} reveals that
 * the credential exists under a different {@code holder_id}, this exception is raised to
 * signal a cross-holder access attempt (architecture.md §5.1 AD-3).</p>
 *
 * <p>Maps to HTTP 403 with {@code error=holder_isolation_violation} in
 * {@link com.eudistack.ebw.keymanager.infrastructure.adapter.http.HybridKeyManagerExceptionHandler}
 * (architecture.md §8.3).</p>
 *
 * <p>The exception message MUST NOT contain the {@code prf_salt} value, the owning
 * {@code holder_id}, or any cryptographic material — it is only used for internal
 * audit logging (NFR-S-537-01, NFR-S-537-02, AC-06).</p>
 *
 * // Intended to be defined in US-01 (EUDISTACK-533). Created here (US-05/EUDISTACK-537)
 * // to fill the gap.
 *
 * <p>Spec: EUDISTACK-537 AC-04, ES-04, NFR-S-537-01, NFR-S-537-02; architecture.md §8.3.</p>
 */
public class HolderIsolationViolationException extends RuntimeException {

    public HolderIsolationViolationException(String credentialId) {
        super("Holder isolation violation for credential: " + credentialId);
    }
}
