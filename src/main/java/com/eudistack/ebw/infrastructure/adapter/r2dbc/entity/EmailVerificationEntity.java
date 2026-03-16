package com.eudistack.ebw.infrastructure.adapter.r2dbc.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("email_verification")
public class EmailVerificationEntity implements Persistable<UUID> {

    @Id
    private UUID id;
    private String userEmail;
    private String codeHash;
    private int attempts;
    private Instant expiresAt;
    private boolean used;
    private Instant createdAt;

    @Transient
    private boolean isNew = false;

    public EmailVerificationEntity() {}

    public EmailVerificationEntity(UUID id, String userEmail, String codeHash, int attempts,
                                   Instant expiresAt, boolean used, Instant createdAt) {
        this.id = id;
        this.userEmail = userEmail;
        this.codeHash = codeHash;
        this.attempts = attempts;
        this.expiresAt = expiresAt;
        this.used = used;
        this.createdAt = createdAt;
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    @Override
    public boolean isNew() { return isNew; }
    public void markNew() { this.isNew = true; }

    public String getUserEmail() { return userEmail; }
    public void setUserEmail(String userEmail) { this.userEmail = userEmail; }
    public String getCodeHash() { return codeHash; }
    public void setCodeHash(String codeHash) { this.codeHash = codeHash; }
    public int getAttempts() { return attempts; }
    public void setAttempts(int attempts) { this.attempts = attempts; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public boolean isUsed() { return used; }
    public void setUsed(boolean used) { this.used = used; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
