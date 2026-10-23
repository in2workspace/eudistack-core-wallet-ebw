package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * A passkey of an account: the WebAuthn credential record (WebAuthn Level 3, "credential
 * record") plus service data (name, user agent, dates).
 *
 * <p>{@code attestedCredentialData} holds the AAGUID, the credential id and the COSE public
 * key (with its algorithm), as serialized by the WebAuthn library. {@code backupEligible}
 * never changes after registration.
 */
public class UserPasskey {

    private final UUID id;
    private final UUID userId;
    private final String credentialId;
    private final byte[] attestedCredentialData;
    private final UUID aaguid;
    private final long signCount;
    private final List<String> transports;
    private final boolean uvInitialized;
    private final boolean backupEligible;
    private final boolean backupState;
    private final String attestationFormat;
    private final boolean prfEnabled;
    private String displayName;
    private final String userAgent;
    private final Instant createdAt;
    private final Instant lastUsedAt;

    @SuppressWarnings("java:S107")
    public UserPasskey(UUID id, UUID userId, String credentialId, byte[] attestedCredentialData, UUID aaguid,
                       long signCount, List<String> transports, boolean uvInitialized, boolean backupEligible,
                       boolean backupState, String attestationFormat, boolean prfEnabled, String displayName,
                       String userAgent, Instant createdAt, Instant lastUsedAt) {
        this.id = id;
        this.userId = userId;
        this.credentialId = credentialId;
        this.attestedCredentialData = attestedCredentialData;
        this.aaguid = aaguid;
        this.signCount = signCount;
        this.transports = transports == null ? List.of() : List.copyOf(transports);
        this.uvInitialized = uvInitialized;
        this.backupEligible = backupEligible;
        this.backupState = backupState;
        this.attestationFormat = attestationFormat;
        this.prfEnabled = prfEnabled;
        this.displayName = displayName;
        this.userAgent = userAgent;
        this.createdAt = createdAt;
        this.lastUsedAt = lastUsedAt;
    }

    /** Builds the passkey of a verified registration. */
    public static UserPasskey register(UUID userId, VerifiedPasskeyRegistration registration, boolean prfEnabled,
                                       String displayName, String userAgent) {
        var now = Instant.now();
        return new UserPasskey(UUID.randomUUID(), userId, registration.credentialId(),
                registration.attestedCredentialData(), registration.aaguid(), registration.signCount(),
                registration.transports(), registration.uvInitialized(), registration.backupEligible(),
                registration.backupState(), registration.attestationFormat(), prfEnabled, displayName, userAgent,
                now, now);
    }

    public void updateDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public String getCredentialId() { return credentialId; }
    public byte[] getAttestedCredentialData() { return attestedCredentialData; }
    public UUID getAaguid() { return aaguid; }
    public long getSignCount() { return signCount; }
    public List<String> getTransports() { return transports; }
    public boolean isUvInitialized() { return uvInitialized; }
    public boolean isBackupEligible() { return backupEligible; }
    public boolean isBackupState() { return backupState; }
    public String getAttestationFormat() { return attestationFormat; }
    public boolean isPrfEnabled() { return prfEnabled; }
    public String getDisplayName() { return displayName; }
    public String getUserAgent() { return userAgent; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastUsedAt() { return lastUsedAt; }
}
