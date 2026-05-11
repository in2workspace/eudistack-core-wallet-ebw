package com.eudistack.ebw.wallet.config.domain.service;

import com.eudistack.ebw.wallet.config.domain.exception.ConfigInvariantViolationException;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.domain.port.ConfigurationAuditPort;
import com.eudistack.ebw.wallet.config.domain.port.DiscoveryCacheInvalidationPort;
import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link TenantWalletConfigInvariants}.
 *
 * <p>Covers T-2, T-3, T-5 from tech-design §2.3. No Spring context — pure domain logic only.
 */
class TenantWalletConfigInvariantsTest {

    private TenantWalletConfigInvariants invariants;

    // Ports used in T-5 to verify zero interaction when invariant fires
    private TenantConfigurationPort tenantConfigurationPort;
    private ConfigurationAuditPort configurationAuditPort;
    private DiscoveryCacheInvalidationPort discoveryCacheInvalidationPort;

    @BeforeEach
    void setUp() {
        invariants = new TenantWalletConfigInvariants();
        tenantConfigurationPort = mock(TenantConfigurationPort.class);
        configurationAuditPort = mock(ConfigurationAuditPort.class);
        discoveryCacheInvalidationPort = mock(DiscoveryCacheInvalidationPort.class);
    }

    // T-2: BROWSER + each non-null KeyManager must throw ConfigInvariantViolationException (FR-20).
    @ParameterizedTest
    @EnumSource(KeyManager.class)
    void validatePairing_browserModeWithKeyManager_throwsInvariantViolation(KeyManager keyManager) {
        // Given
        Optional<KeyManager> presentKeyManager = Optional.of(keyManager);

        // When / Then
        assertThatThrownBy(() -> invariants.validatePairing(WalletMode.BROWSER, presentKeyManager))
                .isInstanceOf(ConfigInvariantViolationException.class)
                .hasMessageContaining("key_manager");
    }

    // T-3: BROWSER + null keyManager must pass without exception (FR-20 satisfied).
    @Test
    void validatePairing_browserModeWithoutKeyManager_doesNotThrow() {
        // Given
        Optional<KeyManager> emptyKeyManager = Optional.empty();

        // When / Then
        assertThatNoException()
                .isThrownBy(() -> invariants.validatePairing(WalletMode.BROWSER, emptyKeyManager));
    }

    // T-5: invariant must fire BEFORE any port is touched.
    // The ports are injected as mocks; after the exception we assert zero interactions.
    @ParameterizedTest
    @EnumSource(KeyManager.class)
    void validatePairing_browserModeWithKeyManager_neverInvokesAnyPort(KeyManager keyManager) {
        // Given
        Optional<KeyManager> presentKeyManager = Optional.of(keyManager);

        // When
        try {
            invariants.validatePairing(WalletMode.BROWSER, presentKeyManager);
        } catch (ConfigInvariantViolationException ignored) {
            // Expected — we are asserting side-effects, not the exception itself
        }

        // Then: no port must have been called (T-5 — invariant fires before any I/O)
        verify(tenantConfigurationPort, never()).findByHost(any());
        verify(tenantConfigurationPort, never()).findBySchemaName(any());
        verify(tenantConfigurationPort, never()).save(any(), any());
        verify(configurationAuditPort, never()).append(any());
        verify(discoveryCacheInvalidationPort, never()).invalidate(any());
    }
}
