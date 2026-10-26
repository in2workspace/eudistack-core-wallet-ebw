package com.eudistack.ebw.infrastructure.adapter.r2dbc.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("refresh_token")
public class RefreshTokenEntity implements Persistable<UUID> {

    @Id
    private UUID id;
    private UUID userId;
    private UUID passkeyId;
    private UUID sessionId;
    private Instant sessionStartedAt;
    private String tokenHash;
    private Instant expiresAt;
    private boolean revoked;
    private Instant createdAt;

    @Transient
    private boolean isNew = false;

    public RefreshTokenEntity() {
        // No-arg constructor required by Spring Data R2DBC to instantiate the entity before populating it
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    @Override
    public boolean isNew() { return isNew; }
    public void markNew() { this.isNew = true; }

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }
    public UUID getPasskeyId() { return passkeyId; }
    public void setPasskeyId(UUID passkeyId) { this.passkeyId = passkeyId; }
    public UUID getSessionId() { return sessionId; }
    public void setSessionId(UUID sessionId) { this.sessionId = sessionId; }
    public Instant getSessionStartedAt() { return sessionStartedAt; }
    public void setSessionStartedAt(Instant sessionStartedAt) { this.sessionStartedAt = sessionStartedAt; }
    public String getTokenHash() { return tokenHash; }
    public void setTokenHash(String tokenHash) { this.tokenHash = tokenHash; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
