package com.eudistack.ebw.keymanager.domain.model;

import jakarta.annotation.Nullable;

import java.util.Map;

/**
 * The derivation material of an attestation obtained with passkey custody: its salt, the passkey it
 * is bound to and, once the attestation is stored, its public key. None of it is a secret on its own.
 *
 * @param passkeyId passkey of the session that created the salt; {@code null} once that passkey was deleted
 * @param publicJwk public key of the attestation; {@code null} until the attestation is stored
 */
public record PrfSalt(String credentialId, byte[] value, @Nullable String passkeyId,
                      @Nullable Map<String, Object> publicJwk) {

    public boolean isOwnedBy(String sessionPasskeyId) {
        return passkeyId != null && passkeyId.equals(sessionPasskeyId);
    }
}
