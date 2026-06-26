package com.eudistack.ebw.keymanager.application;

import reactor.core.publisher.Mono;

/**
 * Application port for PRF salt lifecycle management during hybrid onboarding.
 *
 * <p>Returns the stable 32-byte PRF salt for a given {@code (tenantId, holderId,
 * credentialId)} triple. The salt is generated once per credential on the first call and
 * remains stable for its entire lifetime, ensuring the Wallet PWA always derives the same
 * wrap key across sessions (architecture.md §6.1 step 4).</p>
 *
 *
 * <p>The returned bytes MUST NOT be logged, included in API responses outside of the
 * {@code /onboarding/init} endpoint, or persisted in any location other than
 * {@code hybrid_prf_salt} (NFR-06).</p>
 *
 * <p>Spec: EUDISTACK-534 EC-04; EUDISTACK-537 FR-12; architecture.md §5.1.</p>
 */
public interface PrfSaltUseCase {

    /**
     * Returns the existing PRF salt for the credential, generating and persisting one if
     * this is the first call for this {@code (tenantId, holderId, credentialId)} triple.
     *
     * @param tenantId     the tenant owning the credential (extracted from Reactor context)
     * @param holderId     the holder UUID (DPoP-bound, from controller)
     * @param credentialId the credential being enrolled
     * @return 32-byte raw PRF salt; never empty
     */
    Mono<byte[]> getOrCreatePrfSalt(String tenantId, String holderId, String credentialId);

    /**
     * Read-only lookup of the PRF salt with holder isolation.
     *
     * <p>Used by {@code PrepareSignUseCase} (US-04) during the signing handshake.
     * Unlike {@link #getOrCreatePrfSalt}, this method NEVER generates a new salt —
     * it only reads an existing one, enforcing holder isolation:
     * <ul>
     *   <li>Absent for {@code (holderId, credentialId)} AND {@code countByCredential == 0}
     *       → {@link com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException}
     *       (404 {@code wrap_handle_not_found}).</li>
     *   <li>Absent for this holder but present for another
     *       → {@link com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException}
     *       (403).</li>
     * </ul>
     *
     * @param tenantId     the tenant (for traceability — isolation enforced via DB {@code search_path})
     * @param holderId     the holder UUID (DPoP-bound, never from body — ES-04)
     * @param credentialId the credential being signed
     * @return 32-byte raw PRF salt; never empty
     */
    Mono<byte[]> getForHolder(String tenantId, String holderId, String credentialId);
}