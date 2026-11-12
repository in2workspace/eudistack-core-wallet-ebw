package com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Identifier the Wallet App gives to the attestation it is going to obtain. */
public record CreatePrfSaltRequest(
        @NotBlank @Size(max = 512) @JsonProperty("credential_id") String credentialId
) {
}
