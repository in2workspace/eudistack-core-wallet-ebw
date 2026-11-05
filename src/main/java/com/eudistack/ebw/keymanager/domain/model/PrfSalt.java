package com.eudistack.ebw.keymanager.domain.model;

import jakarta.annotation.Nullable;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

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

    @Override
    public boolean equals(Object other) {
        return other instanceof PrfSalt(String otherCredentialId, byte[] otherValue, String otherPasskeyId,
                                        Map<String, Object> otherPublicJwk)
                && Objects.equals(credentialId, otherCredentialId)
                && Arrays.equals(value, otherValue)
                && Objects.equals(passkeyId, otherPasskeyId)
                && Objects.equals(publicJwk, otherPublicJwk);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(credentialId, passkeyId, publicJwk) + Arrays.hashCode(value);
    }

    /** Leaves the salt bytes out so they never reach a log. */
    @Override
    public String toString() {
        return "PrfSalt[credentialId=" + credentialId + ", passkeyId=" + passkeyId
                + ", publicKeyPresent=" + (publicJwk != null) + "]";
    }
}
