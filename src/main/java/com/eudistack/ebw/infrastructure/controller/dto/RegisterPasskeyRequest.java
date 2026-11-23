package com.eudistack.ebw.infrastructure.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/**
 * Body of {@code POST /auth/passkeys/registration}: {@code credential} is a {@code RegistrationResponseJSON}.
 * Creating a passkey no longer asks for a device name (EUD-8 prd 1.4.0): a {@code displayName} sent by an older
 * Wallet App is ignored.
 */
public record RegisterPasskeyRequest(
        @NotNull UUID ceremonyId,
        @NotNull JsonNode credential,
        Boolean prfSupported
) {
}
