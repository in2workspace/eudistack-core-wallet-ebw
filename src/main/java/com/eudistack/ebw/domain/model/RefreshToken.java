package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.UUID;

public class RefreshToken {

    private UUID id;
    private UUID userId;
    private UUID passkeyId;
    private String tokenHash;
    private Instant expiresAt;
    private boolean revoked;
    private Instant createdAt;

    public RefreshToken(UUID id, UUID userId, UUID passkeyId, String tokenHash,
                        Instant expiresAt, boolean revoked, Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.passkeyId = passkeyId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.revoked = revoked;
        this.createdAt = createdAt;
    }

    public static RefreshToken create(UUID userId, UUID passkeyId, String tokenHash, Instant expiresAt) {
        return new RefreshToken(UUID.randomUUID(), userId, passkeyId, tokenHash, expiresAt, false, Instant.now());
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public void revoke() {
        this.revoked = true;
    }

    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public UUID getPasskeyId() { return passkeyId; }
    public String getTokenHash() { return tokenHash; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public Instant getCreatedAt() { return createdAt; }
}
