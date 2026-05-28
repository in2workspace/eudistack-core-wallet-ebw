package com.eudistack.ebw.keymanager.domain.model;

import java.util.Objects;
import java.util.UUID;

/**
 * Surrogate identity for a holder key record. Wraps a UUID v4 to prevent raw UUID
 * leakage through the domain boundary. Exposed to consumers as an opaque key reference.
 */
public record HolderKeyId(UUID value) {

    public HolderKeyId {
        Objects.requireNonNull(value, "HolderKeyId value must not be null");
    }

    /**
     * Generates a new random HolderKeyId backed by a UUID v4.
     */
    public static HolderKeyId generate() {
        return new HolderKeyId(UUID.randomUUID());
    }

    /**
     * Reconstructs a HolderKeyId from a previously persisted UUID.
     */
    public static HolderKeyId of(UUID value) {
        return new HolderKeyId(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}