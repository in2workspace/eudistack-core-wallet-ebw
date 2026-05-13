package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity.WalletTenantConfigEntity;
import com.eudistack.ebw.wallet.config.infrastructure.controller.dto.DiscoveryResponseDto;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WalletTenantConfigMapper} and {@link DiscoveryResponseDto#from}.
 *
 * <p>Covers T-1/T-2 (EUDISTACK-413 AC-1a, AC-1d) for the {@code server}+{@code db-tde} case:
 * <ul>
 *   <li>A {@link WalletTenantConfigEntity} with {@code walletMode='server'} and
 *       {@code keyManager='db-tde'} maps to a {@link TenantWalletConfigDescriptor} with
 *       {@code walletMode=SERVER} and {@code keyManager=Optional.of(DB_TDE)}.</li>
 *   <li>{@link DiscoveryResponseDto#from} built from a {@code server} descriptor omits
 *       {@code key_manager} — the DTO has no such field (AD-1bis).</li>
 * </ul>
 *
 * <p>No Spring context. No I/O. Does NOT modify or re-test the {@code browser} cases from
 * {@code WalletTenantConfigReadServiceTest}.
 */
class WalletTenantConfigMapperTest {

    // ------------------------------------------------------------------
    // EUDISTACK-413 T-1 — entity server+db-tde → descriptor (AC-1a)
    // ------------------------------------------------------------------

    /**
     * A {@code public.tenant_wallet_config} row with {@code wallet_mode='server'} and
     * {@code key_manager='db-tde'} must map to a descriptor with {@code walletMode=SERVER},
     * {@code keyManager=Optional.of(DB_TDE)}, {@code naturalPersonsOnly=false},
     * {@code supportedCredentials=[]} and the correct {@code version}.
     */
    @Test
    void toDescriptor_serverDbTdeEntity_mapsToServerDescriptorWithKeyManagerPresent() {
        // Given
        WalletTenantConfigEntity entity = buildEntity("dome", "dome.eudistack.example.com",
                "server", "db-tde", false, 1L);

        // When
        TenantWalletConfigDescriptor descriptor = WalletTenantConfigMapper.toDescriptor(entity);

        // Then
        assertThat(descriptor.getSchemaName()).isEqualTo("dome");
        assertThat(descriptor.getHost()).isEqualTo("dome.eudistack.example.com");
        assertThat(descriptor.getWalletMode()).isEqualTo(WalletMode.SERVER);
        assertThat(descriptor.getKeyManager()).isPresent().contains(KeyManager.DB_TDE);
        assertThat(descriptor.isNaturalPersonsOnly()).isFalse();
        assertThat(descriptor.getSupportedCredentials()).isEmpty();
        assertThat(descriptor.getVersion()).isEqualTo(1L);
    }

    // ------------------------------------------------------------------
    // EUDISTACK-413 T-2 — DiscoveryResponseDto.from(server descriptor) omits key_manager (AD-1bis)
    // ------------------------------------------------------------------

    /**
     * {@link DiscoveryResponseDto#from} built from a {@code server}+{@code db-tde} descriptor
     * must produce a DTO with {@code walletMode="server"}, {@code naturalPersonsOnly=false},
     * {@code supportedCredentials=[]}, {@code version=<N>} and — critically — NO {@code key_manager}
     * field (AD-1bis: the public projection intentionally omits it for topology-reconnaissance
     * prevention). This is structurally guaranteed by the DTO record definition, but the test
     * makes the intent explicit and catches any future accidental field addition.
     */
    @Test
    void discoveryResponseDto_fromServerDescriptor_omitsKeyManagerField() {
        // Given
        WalletTenantConfigEntity entity = buildEntity("dome", "dome.eudistack.example.com",
                "server", "db-tde", false, 3L);
        TenantWalletConfigDescriptor descriptor = WalletTenantConfigMapper.toDescriptor(entity);

        // When
        DiscoveryResponseDto dto = DiscoveryResponseDto.from(descriptor);

        // Then — 4-field projection: wallet_mode, natural_persons_only, supported_credentials, version
        assertThat(dto.walletMode()).isEqualTo("server");
        assertThat(dto.naturalPersonsOnly()).isFalse();
        assertThat(dto.supportedCredentials()).isEmpty();
        assertThat(dto.version()).isEqualTo(3L);

        // The DiscoveryResponseDto record has no keyManager() accessor — AD-1bis enforced at
        // compile time. Assert the class does NOT declare such a method.
        assertThat(dto.getClass().getMethods())
                .as("DiscoveryResponseDto must not expose a keyManager accessor (AD-1bis)")
                .noneMatch(m -> m.getName().equals("keyManager") || m.getName().equals("key_manager"));
    }

    // ------------------------------------------------------------------
    // helper
    // ------------------------------------------------------------------

    private static WalletTenantConfigEntity buildEntity(
            String schemaName, String host, String walletMode, String keyManager,
            boolean naturalPersonsOnly, long version) {
        WalletTenantConfigEntity e = new WalletTenantConfigEntity();
        e.setSchemaName(schemaName);
        e.setHost(host);
        e.setWalletMode(walletMode);
        e.setKeyManager(keyManager);
        e.setNaturalPersonsOnly(naturalPersonsOnly);
        e.setVersion(version);
        return e;
    }
}
