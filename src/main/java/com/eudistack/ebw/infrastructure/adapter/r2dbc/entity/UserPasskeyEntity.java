package com.eudistack.ebw.infrastructure.adapter.r2dbc.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("user_passkey")
public class UserPasskeyEntity implements Persistable<UUID> {

    @Id
    private UUID id;
    private UUID userId;
    private String credentialId;
    private byte[] attestedCredentialData;
    private UUID aaguid;
    private long signCount;
    /** JSON array of the transports reported by the browser. */
    private String transports;
    private boolean uvInitialized;
    private boolean backupEligible;
    private boolean backupState;
    private String attestationFormat;
    private boolean prfEnabled;
    private String displayName;
    private String userAgent;
    private Instant createdAt;
    private Instant lastUsedAt;

    @Transient
    private boolean isNew = false;

    public UserPasskeyEntity() {
        // No-arg constructor required by Spring Data R2DBC to instantiate the entity before populating it
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    @Override
    public boolean isNew() { return isNew; }
    public void markNew() { this.isNew = true; }

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }
    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }
    public byte[] getAttestedCredentialData() { return attestedCredentialData; }
    public void setAttestedCredentialData(byte[] attestedCredentialData) { this.attestedCredentialData = attestedCredentialData; }
    public UUID getAaguid() { return aaguid; }
    public void setAaguid(UUID aaguid) { this.aaguid = aaguid; }
    public long getSignCount() { return signCount; }
    public void setSignCount(long signCount) { this.signCount = signCount; }
    public String getTransports() { return transports; }
    public void setTransports(String transports) { this.transports = transports; }
    public boolean isUvInitialized() { return uvInitialized; }
    public void setUvInitialized(boolean uvInitialized) { this.uvInitialized = uvInitialized; }
    public boolean isBackupEligible() { return backupEligible; }
    public void setBackupEligible(boolean backupEligible) { this.backupEligible = backupEligible; }
    public boolean isBackupState() { return backupState; }
    public void setBackupState(boolean backupState) { this.backupState = backupState; }
    public String getAttestationFormat() { return attestationFormat; }
    public void setAttestationFormat(String attestationFormat) { this.attestationFormat = attestationFormat; }
    public boolean isPrfEnabled() { return prfEnabled; }
    public void setPrfEnabled(boolean prfEnabled) { this.prfEnabled = prfEnabled; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(Instant lastUsedAt) { this.lastUsedAt = lastUsedAt; }
}
