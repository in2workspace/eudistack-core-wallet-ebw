package com.eudistack.ebw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Getter
@AllArgsConstructor
public class WalletCredential {

    private UUID id;
    private UUID userId;
    @Setter private String credentialRaw;
    private CredentialFormat format;
    private String credentialConfigId;
    private String kid;
    private String credentialType;
    private String vct;
    private String issuer;
    private String subject;
    private Instant issuanceDate;
    private Instant expirationDate;
    @Setter private CredentialStatus status;
    private Map<String, Object> issuerMetadata;
    private String holderKeyId;
    private Instant createdAt;
    @Setter private Instant updatedAt;

    public static WalletCredential create(UUID userId, String credentialRaw, CredentialFormat format,
                                           String credentialConfigId, String kid, String credentialType,
                                           String vct, String issuer, String subject,
                                           Instant issuanceDate, Instant expirationDate,
                                           Map<String, Object> issuerMetadata, String holderKeyId) {
        var now = Instant.now();
        return new WalletCredential(UUID.randomUUID(), userId, credentialRaw, format,
                credentialConfigId, kid, credentialType, vct, issuer, subject,
                issuanceDate, expirationDate, CredentialStatus.VALID, issuerMetadata, holderKeyId, now, now);
    }
}
