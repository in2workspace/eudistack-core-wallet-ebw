package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.PrfSalt;
import reactor.core.publisher.Mono;

/**
 * Salt of an attestation obtained with passkey custody (EUD-11 design §2.2). It is only given to a
 * session opened with the passkey the attestation belongs to; for any other, the salt does not exist.
 */
public interface PrfSaltUseCase {

    /**
     * Creates the salt of a new attestation bound to the passkey of the session, or returns the one it
     * already created (idempotent per credential and passkey).
     *
     * @throws com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException when the credential
     *         already belongs to another passkey
     */
    Mono<PrfSalt> createForPasskey(String tenantId, String holderId, String passkeyId, String credentialId);

    /**
     * Returns the salt and the public key of an attestation of the passkey of the session.
     *
     * @throws com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException when the attestation
     *         does not exist, is not of the holder, was obtained with another passkey or has no public key yet
     */
    Mono<PrfSalt> getForPasskey(String tenantId, String holderId, String passkeyId, String credentialId);
}
