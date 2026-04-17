package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.WalletCredential;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record CredentialDetailResponse(
        UUID id,
        @JsonProperty("credential_raw") String credentialRaw,
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
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("updated_at") Instant updatedAt
) {
    public static CredentialDetailResponse from(WalletCredential c) {
        return new CredentialDetailResponse(
                c.getId(), c.getCredentialRaw(), c.getFormat().getValue(),
                c.getCredentialConfigId(), c.getCredentialType(), c.getVct(),
                c.getIssuer(), c.getSubject(), c.getIssuanceDate(), c.getExpirationDate(),
                c.getStatus().name(), c.getIssuerMetadata(), c.getKid(),
                c.getCreatedAt(), c.getUpdatedAt()
        );
    }
}
