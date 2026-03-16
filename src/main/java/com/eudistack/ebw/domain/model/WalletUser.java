package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.UUID;

public class WalletUser {

    private UUID id;
    private String email;
    private Instant createdAt;
    private Instant updatedAt;

    public WalletUser(UUID id, String email, Instant createdAt, Instant updatedAt) {
        this.id = id;
        this.email = email;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public static WalletUser create(String email) {
        var now = Instant.now();
        return new WalletUser(UUID.randomUUID(), email, now, now);
    }

    public UUID getId() { return id; }
    public String getEmail() { return email; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
