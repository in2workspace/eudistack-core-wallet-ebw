package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/** Body of {@code PUT /wallet-instances/current} (EUD-15 {@code BindWalletInstanceRequest}). */
public record BindWalletInstanceRequest(@NotNull UUID instanceId) {
}
