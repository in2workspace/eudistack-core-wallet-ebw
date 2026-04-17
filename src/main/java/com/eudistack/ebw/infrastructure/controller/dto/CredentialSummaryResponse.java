package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.WalletCredential;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record CredentialSummaryResponse(
        UUID id,
        String format,
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @JsonProperty("credential_type") String credentialType,
        String vct,
        String issuer,
        String subject,
        @JsonProperty("issuance_date") Instant issuanceDate,
        @JsonProperty("expiration_date") Instant expirationDate,
        String status,
        @JsonProperty("issuer_metadata") Map<String, Object> issuerMetadata,
        String kid,
        @JsonProperty("created_at") Instant createdAt
) {
    public static CredentialSummaryResponse from(WalletCredential c) {
        return new CredentialSummaryResponse(
                c.getId(), c.getFormat().getValue(), c.getCredentialConfigId(),
                c.getCredentialType(), c.getVct(), c.getIssuer(), c.getSubject(),
                c.getIssuanceDate(), c.getExpirationDate(), c.getStatus().name(),
                c.getIssuerMetadata(), c.getKid(), c.getCreatedAt()
        );
    }
}
