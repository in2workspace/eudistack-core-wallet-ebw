package com.eudistack.ebw.wallet.config.infrastructure.controller.dto;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response DTO for the admin wallet tenant configuration endpoints
 * ({@code POST /admin/wallet-tenant-config} → 201, {@code PUT /admin/wallet-tenant-config/{schemaName}} → 200).
 *
 * <p>Unlike the public {@link DiscoveryResponseDto}, this DTO MAY include {@code key_manager}
 * because the admin endpoints are authenticated (the AD-1bis topology-reconnaissance concern
 * does not apply here). For BROWSER-mode tenants {@code key_manager} is always {@code null}
 * (invariant FR-20) and is omitted from the JSON.
 *
 * <p>The JSON uses snake_case names, consistent with {@link DiscoveryResponseDto} and the
 * discovery-plane contract — it deliberately does not serialise the domain aggregate directly
 * (W1: hexagonal layer leak + inconsistent {@code keyManager}/{@code Optional} serialisation).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AdminConfigResponseDto(
        @JsonProperty("schema_name") String schemaName,
        @JsonProperty("host") String host,
        @JsonProperty("wallet_mode") String walletMode,
        @JsonProperty("key_manager") String keyManager,
        @JsonProperty("natural_persons_only") boolean naturalPersonsOnly,
        @JsonProperty("version") long version
) {

    /**
     * Maps a {@link TenantWalletConfigDescriptor} to the admin response DTO.
     *
     * <p>{@code wallet_mode} and {@code key_manager} are serialised using their kebab-/lower-case
     * wire values; {@code key_manager} is {@code null} when absent.
     */
    public static AdminConfigResponseDto from(TenantWalletConfigDescriptor descriptor) {
        return new AdminConfigResponseDto(
                descriptor.getSchemaName(),
                descriptor.getHost(),
                descriptor.getWalletMode().getValue(),
                descriptor.getKeyManager().map(KeyManager::getValue).orElse(null),
                descriptor.isNaturalPersonsOnly(),
                descriptor.getVersion());
    }
}
