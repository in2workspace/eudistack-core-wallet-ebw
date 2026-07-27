package com.eudistack.ebw.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.UUID;

public record RecordActivityRequest(
        @NotNull UUID id,
        @NotBlank @Size(max = 20) String type,
        @NotBlank @Size(max = 255) @JsonProperty("credential_name") String credentialName,
        @NotBlank @Size(max = 1024) String counterparty,
        String details,
        @JsonProperty("shared_attributes") List<String> sharedAttributes
) {}
