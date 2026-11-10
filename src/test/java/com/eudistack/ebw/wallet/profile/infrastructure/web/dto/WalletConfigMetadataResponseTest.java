package com.eudistack.ebw.wallet.profile.infrastructure.web.dto;

import com.eudistack.ebw.domain.model.OnboardingMode;
import com.eudistack.ebw.domain.model.OnboardingSettings;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WalletConfigMetadataResponse#from(TenantWalletProfile, OnboardingSettings)}.
 *
 * <p>Covers AC-01/AC-02: enum values are serialised to lowercase strings; null
 * {@code keyManager} (browser mode) produces {@code null} in the DTO.
 */
class WalletConfigMetadataResponseTest {

    private static final Instant NOW = Instant.parse("2026-05-22T10:00:00Z");
    private static final OnboardingSettings OPEN = new OnboardingSettings(false, OnboardingSettings.DEFAULT_TTL, OnboardingSettings.DEFAULT_REGISTRATION_TTL, null,
            OnboardingMode.OPEN, null);
    private static final TenantWalletProfile BROWSER =
            new TenantWalletProfile("tenant1", WalletMode.BROWSER, null, NOW, NOW);

    @Test
    void from_openMode_hasOnboardingModeOpenAndNoSignupUrl() {
        // Arrange
        var open = new OnboardingSettings(true, OnboardingSettings.DEFAULT_TTL, OnboardingSettings.DEFAULT_REGISTRATION_TTL, null, OnboardingMode.OPEN,
                "https://portal.example.org/");

        // Act
        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(BROWSER, open);

        // Assert
        assertThat(response.onboardingMode()).isEqualTo("open");
        assertThat(response.signupUrl()).isNull();
    }

    @Test
    void from_restrictedMode_hasOnboardingModeAndSignupUrl() {
        // Arrange
        var restricted = new OnboardingSettings(true, OnboardingSettings.DEFAULT_TTL, OnboardingSettings.DEFAULT_REGISTRATION_TTL, null,
                OnboardingMode.RESTRICTED, "https://portal.example.org/");

        // Act
        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(BROWSER, restricted);

        // Assert
        assertThat(response.onboardingMode()).isEqualTo("restricted");
        assertThat(response.signupUrl()).isEqualTo("https://portal.example.org/");
    }

    @Test
    void from_browserMode_producesLowercaseWalletModeAndNullKeyManager() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.BROWSER, null, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile, OPEN);

        assertThat(response.walletMode()).isEqualTo("browser");
        assertThat(response.keyManager()).isNull();
    }

    @Test
    void from_serverMode_producesLowercaseWalletMode() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.DB, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile, OPEN);

        assertThat(response.walletMode()).isEqualTo("server");
    }

    @ParameterizedTest
    @EnumSource(KeyManager.class)
    void from_eachKeyManager_producesLowercaseString(KeyManager keyManager) {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, keyManager, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile, OPEN);

        assertThat(response.keyManager())
                .isNotNull()
                .isEqualTo(keyManager.getDbValue())
                .isEqualTo(keyManager.name().toLowerCase().replace('_', '-'));
    }

    @Test
    void from_dbKeyManager_producesDatabaseValue() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.DB, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile, OPEN);

        assertThat(response.keyManager()).isEqualTo("db");
    }

    @Test
    void from_passkeyPrfKeyManager_producesDatabaseValue() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.PASSKEY_PRF, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile, OPEN);

        assertThat(response.keyManager()).isEqualTo("passkey-prf");
    }

    @Test
    void from_hsmKeyManager_producesDatabaseValue() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.HSM, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile, OPEN);

        assertThat(response.keyManager()).isEqualTo("hsm");
    }

    @Test
    void from_qtspKeyManager_producesDatabaseValue() {
        TenantWalletProfile profile =
                new TenantWalletProfile("tenant1", WalletMode.SERVER, KeyManager.QTSP, NOW, NOW);

        WalletConfigMetadataResponse response = WalletConfigMetadataResponse.from(profile, OPEN);

        assertThat(response.keyManager()).isEqualTo("qtsp");
    }
}
