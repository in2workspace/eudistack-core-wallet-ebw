package com.eudistack.ebw.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.Map;

public record StoreCredentialRequest(
        @NotBlank @JsonProperty("credential_raw") String credentialRaw,
        @NotBlank @Size(max = 50) String format,
        @NotBlank @Size(max = 255) @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @NotBlank @Size(max = 512) String kid,
        @JsonProperty("issuer_metadata") Map<String, Object> issuerMetadata,
        @Size(max = 512) @JsonProperty("holder_key_id") String holderKeyId,
        @JsonProperty("holder_public_jwk") Map<String, Object> holderPublicJwk
) {}
