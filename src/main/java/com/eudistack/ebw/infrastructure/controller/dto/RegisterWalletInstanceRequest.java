package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Body of {@code POST /wallet-instances} (EUD-15 {@code RegisterWalletInstanceRequest}). The name is trimmed and
 * its length checked by the workflow; {@code deviceType} is {@code mobile}, {@code tablet} or {@code desktop}.
 */
public record RegisterWalletInstanceRequest(@NotBlank String displayName, @NotNull String deviceType) {
}
