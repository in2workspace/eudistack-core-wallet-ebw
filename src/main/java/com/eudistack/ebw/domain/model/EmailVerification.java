package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.UUID;

public class EmailVerification {

    private UUID id;
    private String userEmail;
    private String codeHash;
    private int attempts;
    private Instant expiresAt;
    private boolean used;
    private Instant createdAt;

    public EmailVerification(UUID id, String userEmail, String codeHash, int attempts,
                             Instant expiresAt, boolean used, Instant createdAt) {
        this.id = id;
        this.userEmail = userEmail;
        this.codeHash = codeHash;
        this.attempts = attempts;
        this.expiresAt = expiresAt;
        this.used = used;
        this.createdAt = createdAt;
    }

    public static EmailVerification create(String userEmail, String codeHash, Instant expiresAt) {
        return new EmailVerification(UUID.randomUUID(), userEmail, codeHash, 0, expiresAt, false, Instant.now());
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public void incrementAttempts() {
        this.attempts++;
    }

    public void markUsed() {
        this.used = true;
    }

    public UUID getId() { return id; }
    public String getUserEmail() { return userEmail; }
    public String getCodeHash() { return codeHash; }
    public int getAttempts() { return attempts; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isUsed() { return used; }
    public Instant getCreatedAt() { return createdAt; }
}
