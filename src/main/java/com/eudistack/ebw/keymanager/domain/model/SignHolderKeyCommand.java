package com.eudistack.ebw.keymanager.domain.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * Command that drives the {@code SignHolderKey} use case.
 *
 * <p>The {@code signingInput} field carries the raw bytes to be signed. Ownership semantics:
 * the caller provides a defensive copy — this record stores its own internal copy and
 * the accessor returns a defensive copy. This prevents aliased mutation and ensures
 * that {@link #toString()} never leaks the signing material.</p>
 *
 * <p>Invariants validated in the compact constructor:
 * <ul>
 *   <li>{@code keyId}, {@code tenantId}, {@code holderId}, {@code signingType},
 *       {@code purpose}, {@code origin} must not be null.</li>
 *   <li>{@code tenantId} and {@code holderId} must not be blank.</li>
 *   <li>{@code signingInput} must not be null and must not be empty.</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-407, FR-20, FR-21, ADR-021, NFR-SEC-03.</p>
 *
 * @param keyId        opaque surrogate identifier of the holder key (AD-407-4)
 * @param tenantId     the tenant that owns the key
 * @param holderId     the wallet holder who owns the key
 * @param signingType  the type of JWS artefact to produce ({@link SigningType})
 * @param purpose      the purpose of this signing request ({@link SignaturePurpose})
 * @param origin       the consumer system that issued this request ({@link ConsumerOrigin})
 * @param signingInput the raw bytes to sign (opaque from the EBW perspective — EC-03)
 */
public record SignHolderKeyCommand(
        HolderKeyId keyId,
        String tenantId,
        String holderId,
        SigningType signingType,
        SignaturePurpose purpose,
        ConsumerOrigin origin,
        byte[] signingInput
) {

    public SignHolderKeyCommand {
        Objects.requireNonNull(keyId, "keyId must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        if (tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        Objects.requireNonNull(holderId, "holderId must not be null");
        if (holderId.isBlank()) {
            throw new IllegalArgumentException("holderId must not be blank");
        }
        Objects.requireNonNull(signingType, "signingType must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(origin, "origin must not be null");
        Objects.requireNonNull(signingInput, "signingInput must not be null");
        if (signingInput.length == 0) {
            throw new IllegalArgumentException("signingInput must not be empty");
        }
        // Defensive copy — prevents mutation of the caller's array and vice-versa
        signingInput = signingInput.clone();
    }

    /**
     * Returns a defensive copy of the signing input bytes.
     * Callers should zero the returned array after use.
     */
    @Override
    public byte[] signingInput() {
        return signingInput.clone();
    }

    /**
     * Returns a redacted representation — never exposes {@code signingInput} (NFR-SEC-03).
     */
    @Override
    public String toString() {
        return "SignHolderKeyCommand["
                + "keyId=" + keyId
                + ", tenantId=" + tenantId
                + ", holderId=" + holderId
                + ", signingType=" + signingType
                + ", purpose=" + purpose
                + ", origin=" + origin
                + ", signingInput=[REDACTED " + signingInput.length + " bytes]"
                + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SignHolderKeyCommand other)) return false;
        return Objects.equals(keyId, other.keyId)
                && Objects.equals(tenantId, other.tenantId)
                && Objects.equals(holderId, other.holderId)
                && signingType == other.signingType
                && purpose == other.purpose
                && origin == other.origin
                && Arrays.equals(signingInput, other.signingInput);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(keyId, tenantId, holderId, signingType, purpose, origin);
        result = 31 * result + Arrays.hashCode(signingInput);
        return result;
    }
}
