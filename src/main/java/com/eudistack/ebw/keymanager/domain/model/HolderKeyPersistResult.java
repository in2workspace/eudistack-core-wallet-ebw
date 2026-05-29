package com.eudistack.ebw.keymanager.domain.model;

import java.util.Objects;

/**
 * Result returned by {@code HolderKeyWritePort#upsertIfAbsent} to indicate whether a new key
 * was inserted or an existing key was found (idempotent upsert).
 *
 * <p>{@code created} is {@code true} when a new row was inserted,
 * {@code false} when the row already existed for the given
 * {@code (tenantId, holderId, credentialId)} composite key.</p>
 *
 * <p>Spec: ADR-021 (key-per-credential idempotency), EUDISTACK-119 EC-01.</p>
 */
public record HolderKeyPersistResult(
        boolean created,
        HolderKey holderKey
) {

    public HolderKeyPersistResult {
        Objects.requireNonNull(holderKey, "holderKey must not be null");
    }
}
