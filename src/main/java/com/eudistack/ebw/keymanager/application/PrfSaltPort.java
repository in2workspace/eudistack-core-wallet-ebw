package com.eudistack.ebw.keymanager.application;

import reactor.core.publisher.Mono;

/**
 * Outgoing port for PRF salt persistence.
 *
 * <p>Defines the contract that the {@code hybrid_prf_salt} storage adapter must implement.
 * The port is declared in the application layer; the R2DBC implementation lives in
 * {@code infrastructure.adapter.r2dbc} (technical-design.md §3.2 AD-4).</p>
 *
 * <p>The composite primary key {@code (holder_id, credential_id)} is the uniqueness
 * invariant (architecture.md §5.1 AD-3). INSERT on a duplicate key is treated as a
 * benign signal in get-or-create scenarios (EC-03).</p>
 *
 * <p>Spec: EUDISTACK-537 AC-01, AC-03, AC-08; architecture.md §5.1.</p>
 */
public interface PrfSaltPort {

    /**
     * Returns the raw 32-byte PRF salt for the given holder and credential.
     *
     * <p>Returns an empty {@link Mono} when no salt has been stored yet for
     * {@code (holderId, credentialId)}. Never throws on a not-found condition.</p>
     *
     * @param holderId     the holder UUID (DPoP-bound, from controller)
     * @param credentialId the credential identifier
     * @return 32-byte PRF salt, or empty if not found
     */
    Mono<byte[]> findBy(String holderId, String credentialId);

    /**
     * Persists a new PRF salt for the given holder and credential.
     *
     * <p>On a duplicate-key violation (concurrent get-or-create race), the exception is
     * swallowed silently. The caller must re-SELECT to obtain the winner's value (EC-03).</p>
     *
     * @param holderId     the holder UUID (DPoP-bound, from controller)
     * @param credentialId the credential identifier
     * @param prfSalt      exactly 32 raw bytes; not base64/hex-encoded
     * @return empty Mono on success
     */
    Mono<Void> insert(String holderId, String credentialId, byte[] prfSalt);

    /**
     * Returns the count of distinct salt rows for the given credential across all holders.
     *
     * <p>Used by the {@code salt_coherent} health indicator to detect missing or duplicate
     * rows (AC-08). The result is 0 if no salt has been stored, 1 in the normal case
     * (one holder per credential in the tenant scope), or &gt;1 if multiple holders share
     * the same credential identifier — which is valid but must be counted correctly.</p>
     *
     * @param credentialId the credential identifier
     * @return row count for this credential
     */
    Mono<Long> countByCredential(String credentialId);
}
