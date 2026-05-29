package com.eudistack.ebw.wallet.profile.domain.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TenantWalletProfileTest {

    private static final Instant NOW = Instant.parse("2026-05-21T10:00:00Z");

    @Test
    void constructor_browserWithNullKeyManager_succeeds() {
        TenantWalletProfile profile =
                new TenantWalletProfile("t1", WalletMode.BROWSER, null, NOW, NOW);

        assertThat(profile.tenant()).isEqualTo("t1");
        assertThat(profile.walletMode()).isEqualTo(WalletMode.BROWSER);
        assertThat(profile.keyManager()).isNull();
    }

    @ParameterizedTest
    @EnumSource(KeyManager.class)
    void constructor_serverWithAnyKeyManager_succeeds(KeyManager km) {
        TenantWalletProfile profile =
                new TenantWalletProfile("t1", WalletMode.SERVER, km, NOW, NOW);

        assertThat(profile.walletMode()).isEqualTo(WalletMode.SERVER);
        assertThat(profile.keyManager()).isEqualTo(km);
    }

    @ParameterizedTest
    @EnumSource(KeyManager.class)
    void constructor_browserWithNonNullKeyManager_throwsIllegalArgumentException(KeyManager km) {
        assertThatThrownBy(
                () -> new TenantWalletProfile("t1", WalletMode.BROWSER, km, NOW, NOW))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("FR-10");
    }

    @Test
    void constructor_serverWithNullKeyManager_throwsIllegalArgumentException() {
        assertThatThrownBy(
                () -> new TenantWalletProfile("t1", WalletMode.SERVER, null, NOW, NOW))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("FR-11");
    }

    @Test
    void constructor_nullTenant_throwsNullPointerException() {
        assertThatThrownBy(
                () -> new TenantWalletProfile(null, WalletMode.BROWSER, null, NOW, NOW))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("tenant");
    }

    @Test
    void constructor_nullWalletMode_throwsNullPointerException() {
        assertThatThrownBy(
                () -> new TenantWalletProfile("t1", null, null, NOW, NOW))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("walletMode");
    }

    @Test
    void constructor_nullCreatedAt_throwsNullPointerException() {
        assertThatThrownBy(
                () -> new TenantWalletProfile("t1", WalletMode.BROWSER, null, null, NOW))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("createdAt");
    }

    @Test
    void constructor_nullUpdatedAt_throwsNullPointerException() {
        assertThatThrownBy(
                () -> new TenantWalletProfile("t1", WalletMode.BROWSER, null, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("updatedAt");
    }
}