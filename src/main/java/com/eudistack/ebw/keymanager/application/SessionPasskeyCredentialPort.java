package com.eudistack.ebw.keymanager.application;

import reactor.core.publisher.Mono;

/**
 * Outgoing port: whether a stored attestation of the holder, identified by its holder key
 * ({@code wallet_credential.holder_key_id}), was obtained with a given passkey.
 *
 * <p>Used by the passkey custody signing handshake to deliver the PRF salt only for the
 * attestations of the session's passkey (EUD-11 FR-14).
 */
public interface SessionPasskeyCredentialPort {

    Mono<Boolean> isObtainedWithPasskey(String holderId, String credentialId, String passkeyId);
}
