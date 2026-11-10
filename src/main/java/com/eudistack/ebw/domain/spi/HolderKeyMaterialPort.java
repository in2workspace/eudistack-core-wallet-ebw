package com.eudistack.ebw.domain.spi;

import com.eudistack.ebw.domain.model.CustodyMode;
import com.eudistack.ebw.domain.model.WalletCredential;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/**
 * What the attestation workflows need from the key custody: to check that an attestation is bound to the
 * key of its holder, and to delete that key's material when the attestation is deleted (EUD-11 FR-05, FR-10, FR-16).
 */
public interface HolderKeyMaterialPort {

    /**
     * @param cnfJwk          public key the attestation is bound to
     * @param holderPublicJwk public key the Wallet App derived; only with passkey custody
     */
    record Binding(CustodyMode mode, UUID userId, UUID passkeyId, String holderKeyId,
                   Map<String, Object> cnfJwk, Map<String, Object> holderPublicJwk) {
    }

    /**
     * Compares the fingerprints (RFC 7638) of the attestation's key and of its holder key.
     *
     * @return empty when they match
     * @throws com.eudistack.ebw.domain.model.exception.HolderKeyMismatchException when they do not
     */
    Mono<Void> verify(Binding binding);

    /** Keeps the public key of an attestation obtained with passkey custody; a no-op with server custody. */
    Mono<Void> keepPublicKey(Binding binding);

    /** Deletes the key material of the attestation; a no-op for an attestation without custody mode. */
    Mono<Void> delete(WalletCredential credential);
}
