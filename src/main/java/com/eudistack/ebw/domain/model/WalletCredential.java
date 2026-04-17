package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public class WalletCredential {

    private UUID id;
    private UUID userId;
    private String credentialRaw;
    private CredentialFormat format;
    private String credentialConfigId;
    private String kid;
    private String credentialType;
    private String vct;
    private String issuer;
    private String subject;
    private Instant issuanceDate;
    private Instant expirationDate;
    private CredentialStatus status;
    private Map<String, Object> issuerMetadata;
    private Instant createdAt;
    private Instant updatedAt;

    public WalletCredential(UUID id, UUID userId, String credentialRaw, CredentialFormat format,
                            String credentialConfigId, String kid, String credentialType, String vct,
                            String issuer, String subject, Instant issuanceDate, Instant expirationDate,
                            CredentialStatus status, Map<String, Object> issuerMetadata,
                            Instant createdAt, Instant updatedAt) {
        this.id = id;
        this.userId = userId;
        this.credentialRaw = credentialRaw;
        this.format = format;
        this.credentialConfigId = credentialConfigId;
        this.kid = kid;
        this.credentialType = credentialType;
        this.vct = vct;
        this.issuer = issuer;
        this.subject = subject;
        this.issuanceDate = issuanceDate;
        this.expirationDate = expirationDate;
        this.status = status;
        this.issuerMetadata = issuerMetadata;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public static WalletCredential create(UUID userId, String credentialRaw, CredentialFormat format,
                                           String credentialConfigId, String kid, String credentialType,
                                           String vct, String issuer, String subject,
                                           Instant issuanceDate, Instant expirationDate,
                                           Map<String, Object> issuerMetadata) {
        var now = Instant.now();
        return new WalletCredential(UUID.randomUUID(), userId, credentialRaw, format,
                credentialConfigId, kid, credentialType, vct, issuer, subject,
                issuanceDate, expirationDate, CredentialStatus.VALID, issuerMetadata, now, now);
    }

    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public String getCredentialRaw() { return credentialRaw; }
    public CredentialFormat getFormat() { return format; }
    public String getCredentialConfigId() { return credentialConfigId; }
    public String getKid() { return kid; }
    public String getCredentialType() { return credentialType; }
    public String getVct() { return vct; }
    public String getIssuer() { return issuer; }
    public String getSubject() { return subject; }
    public Instant getIssuanceDate() { return issuanceDate; }
    public Instant getExpirationDate() { return expirationDate; }
    public CredentialStatus getStatus() { return status; }
    public Map<String, Object> getIssuerMetadata() { return issuerMetadata; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void setCredentialRaw(String credentialRaw) { this.credentialRaw = credentialRaw; }
    public void setStatus(CredentialStatus status) { this.status = status; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
