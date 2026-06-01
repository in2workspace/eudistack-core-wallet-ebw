package com.eudistack.ebw.infrastructure.adapter.r2dbc.entity;

import io.r2dbc.postgresql.codec.Json;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("wallet_credential")
public class WalletCredentialEntity implements Persistable<UUID> {

    @Id
    private UUID id;
    private UUID userId;
    private String credentialRaw;
    private String format;
    private String credentialConfigId;
    private String kid;
    private String credentialType;
    private String vct;
    private String issuer;
    private String subject;
    private Instant issuanceDate;
    private Instant expirationDate;
    private String status;
    private Json issuerMetadata;
    @Column("holder_key_id")
    private String holderKeyId;
    private Instant createdAt;
    private Instant updatedAt;

    @Transient
    private boolean isNew = false;

    public WalletCredentialEntity() {}

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    @Override
    public boolean isNew() { return isNew; }
    public void markNew() { this.isNew = true; }

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }
    public String getCredentialRaw() { return credentialRaw; }
    public void setCredentialRaw(String credentialRaw) { this.credentialRaw = credentialRaw; }
    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }
    public String getCredentialConfigId() { return credentialConfigId; }
    public void setCredentialConfigId(String credentialConfigId) { this.credentialConfigId = credentialConfigId; }
    public String getKid() { return kid; }
    public void setKid(String kid) { this.kid = kid; }
    public String getCredentialType() { return credentialType; }
    public void setCredentialType(String credentialType) { this.credentialType = credentialType; }
    public String getVct() { return vct; }
    public void setVct(String vct) { this.vct = vct; }
    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public Instant getIssuanceDate() { return issuanceDate; }
    public void setIssuanceDate(Instant issuanceDate) { this.issuanceDate = issuanceDate; }
    public Instant getExpirationDate() { return expirationDate; }
    public void setExpirationDate(Instant expirationDate) { this.expirationDate = expirationDate; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public Json getIssuerMetadata() { return issuerMetadata; }
    public void setIssuerMetadata(Json issuerMetadata) { this.issuerMetadata = issuerMetadata; }
    public String getHolderKeyId() { return holderKeyId; }
    public void setHolderKeyId(String holderKeyId) { this.holderKeyId = holderKeyId; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
