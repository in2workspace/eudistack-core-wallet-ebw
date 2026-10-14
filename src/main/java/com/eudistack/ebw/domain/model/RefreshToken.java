package com.eudistack.ebw.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Refresh token of a session. All the tokens of a rotation family share {@code sessionId}
 * and {@code sessionStartedAt}: the family is the session. Every session is opened with a
 * verified passkey, so {@code passkeyId} is always set.
 */
public class RefreshToken {

    private final UUID id;
    private final UUID userId;
    private final UUID passkeyId;
    private final UUID sessionId;
    private final Instant sessionStartedAt;
    private final String tokenHash;
    private final Instant expiresAt;
    private final boolean revoked;
    private final Instant createdAt;

    @SuppressWarnings("java:S107")
    public RefreshToken(UUID id, UUID userId, UUID passkeyId, UUID sessionId, Instant sessionStartedAt,
                        String tokenHash, Instant expiresAt, boolean revoked, Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.passkeyId = passkeyId;
        this.sessionId = sessionId;
        this.sessionStartedAt = sessionStartedAt;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.revoked = revoked;
        this.createdAt = createdAt;
    }

    public static RefreshToken create(UUID userId, UUID passkeyId, UUID sessionId, Instant sessionStartedAt,
                                      String tokenHash, Instant expiresAt) {
        return new RefreshToken(UUID.randomUUID(), userId, passkeyId, sessionId, sessionStartedAt, tokenHash,
                expiresAt, false, Instant.now());
    }

    /** Inactivity limit: the token expires an idle period after it was issued. */
    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }

    /** Absolute limit: the session cannot be renewed past its maximum duration. */
    public boolean isPastMaxDuration(Instant now, Duration maxDuration) {
        return now.isAfter(sessionStartedAt.plus(maxDuration));
    }

    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public UUID getPasskeyId() { return passkeyId; }
    public UUID getSessionId() { return sessionId; }
    public Instant getSessionStartedAt() { return sessionStartedAt; }
    public String getTokenHash() { return tokenHash; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public Instant getCreatedAt() { return createdAt; }
}
