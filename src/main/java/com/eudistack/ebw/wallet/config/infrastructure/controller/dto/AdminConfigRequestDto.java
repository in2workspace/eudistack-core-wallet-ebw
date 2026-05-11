package com.eudistack.ebw.wallet.config.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/**
 * Request DTO for the admin wallet tenant configuration endpoints.
 *
 * <p>Used by both {@code POST /admin/wallet-tenant-config} (create) and
 * {@code PUT /admin/wallet-tenant-config/{schemaName}} (update).
 *
 * <p>The {@code key_manager} field is intentionally nullable — BROWSER-mode tenants
 * must have {@code key_manager=null} (invariant FR-20). The invariant is enforced by
 * {@code TenantWalletConfigInvariants} in the domain layer, not by a Bean Validation
 * constraint here, so that a precise RFC 9457 409 Conflict response can be returned.
 *
 * <p>The {@code version} field is the optimistic-lock expectation on PUT: when present and the
 * tenant already exists, the update only succeeds if the stored version matches; otherwise the
 * endpoint returns HTTP 409 {@code urn:eudistack:error:config-version-conflict}. On POST (create)
 * the field is ignored.
 */
public record AdminConfigRequestDto(

        @JsonProperty("schema_name")
        @NotBlank(message = "schema_name is required")
        @Pattern(regexp = "^[a-z][a-z0-9_]{0,62}$",
                message = "schema_name must be a valid PostgreSQL identifier (lowercase, starts with letter, max 63 chars)")
        String schemaName,

        @JsonProperty("host")
        @NotBlank(message = "host is required")
        String host,

        @JsonProperty("wallet_mode")
        @NotNull(message = "wallet_mode is required")
        String walletMode,

        @JsonProperty("key_manager")
        String keyManager,

        @JsonProperty("natural_persons_only")
        Boolean naturalPersonsOnly,

        @JsonProperty("version")
        Long version
) {
}
