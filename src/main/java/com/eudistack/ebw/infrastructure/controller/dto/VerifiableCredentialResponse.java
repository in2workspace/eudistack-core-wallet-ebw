package com.eudistack.ebw.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record VerifiableCredentialResponse(
        @JsonProperty("@context") List<String> context,
        String id,
        List<String> type,
        String lifeCycleStatus,
        String name,
        String description,
        IssuerDto issuer,
        String validFrom,
        String validUntil,
        Object credentialSubject,
        CredentialStatusDto credentialStatus,
        String credentialEncoded,
        String credentialFormat
) {

    public record IssuerDto(
            String id,
            String organization,
            String organizationIdentifier,
            String country,
            String commonName,
            String serialNumber
    ) {}

    public record CredentialStatusDto(
            String id,
            String type,
            String statusPurpose,
            String statusListIndex,
            String statusListCredential
    ) {}
}
