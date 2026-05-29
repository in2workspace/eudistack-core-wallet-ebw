package com.eudistack.ebw.keymanager.domain.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Aggregate root representing a holder key pair bound to a specific credential.
 *
 * <p>Per ADR-021: one key pair is generated per {@code (tenantId, holderId, credentialId)}
 * tuple. Idempotency is enforced at the database level (composite primary key) and at the
 * use-case level via UPSERT-ON-CONFLICT (EC-01).</p>
 *
 * <p>The {@code privateKey} field stores raw PKCS#8 / SEC 1 bytes as returned by the JCA.
 * At-rest protection is provided exclusively by RDS Transparent Data Encryption (ADR-099).
 * No application-level cipher is applied.</p>
 *
 * <p>Security: {@link #toString()} redacts {@code privateKey} to prevent accidental
 * exposure in logs or exception messages (NFR-SEC-03, R-119-1).</p>
 *
 * <p>Spec: OID4VCI 1.0 §8.2, ADR-021, ADR-099, SAD-DEC-006.</p>
 */
public record HolderKey(
        HolderKeyId id,
        String tenantId,
        String holderId,
        String credentialId,
        CredentialFormat format,
        KeyAlgorithm algorithm,
        byte[] privateKey,
        JwkPublic publicJwk,
        Instant createdAt,
        Instant revokedAt
) {

    public HolderKey {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        if (tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        Objects.requireNonNull(holderId, "holderId must not be null");
        if (holderId.isBlank()) {
            throw new IllegalArgumentException("holderId must not be blank");
        }
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        if (credentialId.isBlank()) {
            throw new IllegalArgumentException("credentialId must not be blank");
        }
        Objects.requireNonNull(format, "format must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        if (privateKey.length == 0) {
            throw new IllegalArgumentException("privateKey must not be empty");
        }
        Objects.requireNonNull(publicJwk, "publicJwk must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        // revokedAt is intentionally nullable — null means the key is still active
        privateKey = privateKey.clone();
    }

    /**
     * Returns a defensive copy of the private key bytes.
     * Callers are responsible for zeroing the returned array after use.
     */
    @Override
    public byte[] privateKey() {
        return privateKey.clone();
    }

    /**
     * Returns true if this key has been revoked.
     */
    public boolean isRevoked() {
        return revokedAt != null;
    }

    /**
     * Returns a string representation that redacts the private key bytes.
     * This override is a security guard against accidental log exposure (R-119-1).
     */
    @Override
    public String toString() {
        return "HolderKey["
                + "id=" + id
                + ", tenantId=" + tenantId
                + ", holderId=" + holderId
                + ", credentialId=" + credentialId
                + ", format=" + format
                + ", algorithm=" + algorithm
                + ", privateKey=[REDACTED]"
                + ", publicJwk=" + publicJwk
                + ", createdAt=" + createdAt
                + ", revokedAt=" + revokedAt
                + "]";
    }
}