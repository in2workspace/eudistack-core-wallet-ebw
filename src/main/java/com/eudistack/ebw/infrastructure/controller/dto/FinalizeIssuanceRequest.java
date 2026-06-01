package com.eudistack.ebw.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.Map;

public record FinalizeIssuanceRequest(
        @NotNull @JsonProperty("credentialResponseWithStatus") CredentialResponseWithStatus credentialResponseWithStatus,
        @NotBlank String format,
        @NotBlank @JsonProperty("credentialConfigurationId") String credentialConfigurationId,
        @JsonProperty("issuerMetadata") Map<String, Object> issuerMetadata,
        @Nullable @JsonProperty("holderKeyId") String holderKeyId,
        @Nullable @JsonProperty("holderKid") String holderKid
) {
    public record CredentialResponseWithStatus(
            @JsonProperty("credentialResponse") CredentialResponse credentialResponse
    ) {}

    public record CredentialResponse(
            List<CredentialItem> credentials
    ) {}

    public record CredentialItem(
            String credential
    ) {}

    public String extractCredentialRaw() {
        if (credentialResponseWithStatus == null
                || credentialResponseWithStatus.credentialResponse() == null
                || credentialResponseWithStatus.credentialResponse().credentials() == null
                || credentialResponseWithStatus.credentialResponse().credentials().isEmpty()) {
            throw new IllegalArgumentException("No credential found in credential response");
        }
        return credentialResponseWithStatus.credentialResponse().credentials().get(0).credential();
    }
}
