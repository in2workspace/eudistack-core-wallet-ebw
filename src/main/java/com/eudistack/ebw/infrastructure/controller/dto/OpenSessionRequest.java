package com.eudistack.ebw.infrastructure.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/** Body of {@code POST /auth/sessions}: {@code credential} is an {@code AuthenticationResponseJSON}. */
public record OpenSessionRequest(
        @NotNull UUID ceremonyId,
        @NotNull JsonNode credential
) {
}
