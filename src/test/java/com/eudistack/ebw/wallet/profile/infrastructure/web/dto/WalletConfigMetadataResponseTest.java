package com.eudistack.ebw.wallet.profile.infrastructure.web.dto;

import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WalletConfigMetadataResponse#from(TenantWalletProfile)}.
 *
 * <p>Covers AC-01/AC-02: enum values are serialised to lowercase strings; null
 * {@code keyManager} (browser mode) produces {@code null} in the DTO.
 */
class WalletConfigMetadataResponseTest {

    private static final Instant NOW = Instant.parse("2026-05-22T10:00:00Z");

    @Test
    void from_browserMode_producesLowercaseWalletModeAndNullKeyManager() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.BROWSER, null, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile);

        assertThat(response.walletMode()).isEqualTo("browser");
        assertThat(response.keyManager()).isNull();
    }

    @Test
    void from_serverMode_producesLowercaseWalletMode() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.DB, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile);

        assertThat(response.walletMode()).isEqualTo("server");
    }

    @ParameterizedTest
    @EnumSource(KeyManager.class)
    void from_eachKeyManager_producesLowercaseString(KeyManager keyManager) {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, keyManager, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile);

        assertThat(response.keyManager())
                .isNotNull()
                .isEqualTo(keyManager.getDbValue())
                .isEqualTo(keyManager.name().toLowerCase());
    }

    @Test
    void from_dbKeyManager_producesDatabaseValue() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.DB, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile);

        assertThat(response.keyManager()).isEqualTo("db");
    }

    @Test
    void from_hybridKeyManager_producesDatabaseValue() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.HYBRID, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile);

        assertThat(response.keyManager()).isEqualTo("hybrid");
    }

    @Test
    void from_hsmKeyManager_producesDatabaseValue() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.HSM, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile);

        assertThat(response.keyManager()).isEqualTo("hsm");
    }

    @Test
    void from_qtspKeyManager_producesDatabaseValue() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.QTSP, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile);

        assertThat(response.keyManager()).isEqualTo("qtsp");
    }
}
