package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.NotBlank;

/** Body of {@code PATCH /wallet-instances/{id}} (EUD-15 {@code RenameWalletInstanceRequest}): trimmed by the service. */
public record RenameWalletInstanceRequest(@NotBlank String displayName) {
}
