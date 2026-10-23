package com.eudistack.ebw.infrastructure.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

/** Body of {@code POST /auth/passkeys/registration}: {@code credential} is a {@code RegistrationResponseJSON}. */
public record RegisterPasskeyRequest(
        @NotNull UUID ceremonyId,
        @NotNull JsonNode credential,
        Boolean prfSupported,
        @Size(min = 1, max = 100) String displayName
) {
}
