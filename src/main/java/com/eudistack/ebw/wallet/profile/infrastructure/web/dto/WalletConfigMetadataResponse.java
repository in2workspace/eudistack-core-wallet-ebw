package com.eudistack.ebw.wallet.profile.infrastructure.web.dto;

import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * HTTP response DTO for {@code GET /.well-known/wallet-config-metadata}.
 *
 * <p>Serialization rules (AC-01/AC-02):
 * <ul>
 *   <li>{@code walletMode} — lowercase string: {@code "browser"} or {@code "server"}.
 *   <li>{@code keyManager} — lowercase string when present; {@code null} / absent when the
 *       wallet mode is {@code BROWSER} (FR-10).
 * </ul>
 *
 * <p>The static factory {@link #from(TenantWalletProfile)} is the only construction path;
 * enum values are converted to their {@code dbValue} (lowercase) string directly.
 *
 * <p>See technical-design.md §3.2 (DTO row) and acceptance-criteria.md AC-01/AC-02.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record WalletConfigMetadataResponse(
        @JsonProperty("wallet_mode") String walletMode,
        @JsonProperty("key_manager") String keyManager
) {

    /**
     * Creates a response DTO from the domain record.
     *
     * <p>Enum-to-string conversion uses the enum's {@code dbValue} (lowercase), which is
     * already the canonical API representation defined in the SRS.
     *
     * @param profile the domain record — must not be {@code null}
     * @return the populated response DTO; {@code key_manager} is {@code null} for browser mode
     */
    public static WalletConfigMetadataResponse from(TenantWalletProfile profile) {
        String walletModeStr = profile.walletMode().getDbValue();
        String keyManagerStr = profile.keyManager() != null
                ? profile.keyManager().getDbValue()
                : null;
        return new WalletConfigMetadataResponse(walletModeStr, keyManagerStr);
    }
}
