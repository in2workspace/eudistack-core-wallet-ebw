package com.eudistack.ebw.infrastructure.adapter.r2dbc.entity;

import io.r2dbc.postgresql.codec.Json;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("wallet_activity")
public class WalletActivityEntity implements Persistable<UUID> {

    @Id
    private UUID id;
    private UUID userId;
    private String type;
    private String credentialName;
    private String counterparty;
    private String details;
    private Json sharedAttributes;
    private Instant createdAt;

    @Transient
    private boolean isNew = false;

    public WalletActivityEntity() {}

    public WalletActivityEntity(UUID id, UUID userId, String type, String credentialName,
                                 String counterparty, String details, Json sharedAttributes,
                                 Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.type = type;
        this.credentialName = credentialName;
        this.counterparty = counterparty;
        this.details = details;
        this.sharedAttributes = sharedAttributes;
        this.createdAt = createdAt;
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    @Override
    public boolean isNew() { return isNew; }
    public void markNew() { this.isNew = true; }

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getCredentialName() { return credentialName; }
    public void setCredentialName(String credentialName) { this.credentialName = credentialName; }
    public String getCounterparty() { return counterparty; }
    public void setCounterparty(String counterparty) { this.counterparty = counterparty; }
    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }
    public Json getSharedAttributes() { return sharedAttributes; }
    public void setSharedAttributes(Json sharedAttributes) { this.sharedAttributes = sharedAttributes; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
