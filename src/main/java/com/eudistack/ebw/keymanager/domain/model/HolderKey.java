package com.eudistack.ebw.keymanager.domain.model;

import com.eudistack.ebw.domain.model.CredentialFormat;

import java.time.Instant;
import java.util.Objects;

public record HolderKey(
        String keyId,
        String holderId,
        String credentialId,
        String tenantId,
        byte[] privateKey,
        String publicJwk,
        String algorithm,
        CredentialFormat format,
        Instant createdAt,
        Instant revokedAt
) {

    public HolderKey {
        Objects.requireNonNull(keyId, "keyId must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        if (privateKey.length == 0) {
            throw new IllegalArgumentException("privateKey must not be empty");
        }
        Objects.requireNonNull(publicJwk, "publicJwk must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(format, "format must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        privateKey = privateKey.clone();
    }

    @Override
    public byte[] privateKey() {
        return privateKey.clone();
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    @Override
    public String toString() {
        return "HolderKey[keyId=" + keyId +
                ", credentialId=" + credentialId +
                ", tenantId=" + tenantId +
                ", holderId=[REDACTED]" +
                ", privateKey=[REDACTED]" +
                ", algorithm=" + algorithm +
                ", format=" + format +
                ", createdAt=" + createdAt +
                ", revokedAt=" + revokedAt + "]";
    }
}