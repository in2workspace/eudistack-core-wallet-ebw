package com.eudistack.ebw.keymanager.domain.model;

import java.util.Objects;

/**
 * Result produced by the {@code GenerateHolderKeyUseCase} after a successful key generation
 * or idempotent fetch.
 *
 * <p>{@code created} is {@code true} when a new key pair was generated and persisted,
 * {@code false} when an existing key was fetched due to a concurrent request for the same
 * {@code (tenantId, holderId, credentialId)} tuple (EC-01 idempotency, ADR-021).</p>
 *
 * <p>The consumer can use {@code created} to distinguish audit semantics:
 * {@code key.generated} vs {@code key.fetched} per AD-119-3.</p>
 */
public record HolderKeyResult(
        HolderKeyId keyId,
        JwkPublic publicJwk,
        JwsProof jwsProof,
        boolean created
) {

    public HolderKeyResult {
        Objects.requireNonNull(keyId, "keyId must not be null");
        Objects.requireNonNull(publicJwk, "publicJwk must not be null");
        Objects.requireNonNull(jwsProof, "jwsProof must not be null");
    }
}