package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.PrfSalt;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Outgoing port for the {@code passkey_prf_salt} table.
 *
 * <p>The composite primary key {@code (holder_id, credential_id)} is the uniqueness invariant.
 * Tenant isolation is enforced by the PostgreSQL {@code search_path} set per request.</p>
 */
public interface PrfSaltPort {

    /** @return the salt of the attestation of the holder, or empty when there is none */
    Mono<PrfSalt> findBy(String holderId, String credentialId);

    /**
     * Persists a new salt bound to a passkey. A duplicate key (concurrent get-or-create race) is not an
     * error: the caller reads the winner's row.
     *
     * @param prfSalt exactly 32 raw bytes
     * @return {@code true} when this call inserted the row
     */
    Mono<Boolean> insert(String holderId, String credentialId, String passkeyId, byte[] prfSalt);

    /**
     * Keeps the public key of the attestation in the row of a salt of the given passkey.
     *
     * @return {@code true} when the row exists, belongs to the passkey and had no public key yet
     */
    Mono<Boolean> setPublicJwk(String holderId, String credentialId, String passkeyId, Map<String, Object> publicJwk);

    /** @return {@code true} when a row was deleted */
    Mono<Boolean> delete(String holderId, String credentialId);
}
