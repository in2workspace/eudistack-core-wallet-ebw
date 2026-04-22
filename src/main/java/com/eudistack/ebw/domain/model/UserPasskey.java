package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.UUID;

public class UserPasskey {

    private UUID id;
    private UUID userId;
    private String credentialId;
    private String displayName;
    private String userAgent;
    private Instant createdAt;
    private Instant lastUsedAt;

    public UserPasskey(UUID id, UUID userId, String credentialId, String displayName,
                       String userAgent, Instant createdAt, Instant lastUsedAt) {
        this.id = id;
        this.userId = userId;
        this.credentialId = credentialId;
        this.displayName = displayName;
        this.userAgent = userAgent;
        this.createdAt = createdAt;
        this.lastUsedAt = lastUsedAt;
    }

    public static UserPasskey create(UUID userId, String credentialId, String displayName, String userAgent) {
        var now = Instant.now();
        return new UserPasskey(UUID.randomUUID(), userId, credentialId, displayName, userAgent, now, now);
    }

    public void updateDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public void touchLastUsed() {
        this.lastUsedAt = Instant.now();
    }

    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public String getCredentialId() { return credentialId; }
    public String getDisplayName() { return displayName; }
    public String getUserAgent() { return userAgent; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastUsedAt() { return lastUsedAt; }
}
