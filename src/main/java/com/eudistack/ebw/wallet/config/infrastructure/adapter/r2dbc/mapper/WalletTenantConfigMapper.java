package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity.WalletTenantConfigEntity;

import java.util.Collections;
import java.util.Optional;

/**
 * Maps a {@link WalletTenantConfigEntity} row to the domain aggregate
 * {@link TenantWalletConfigDescriptor} on the discovery read path.
 *
 * <p>Pure static utility — no Spring, no I/O.
 *
 * <p>{@code supportedCredentials} is not persisted in the entity in this Story (US-01);
 * the mapper always returns an empty list on read.
 */
public final class WalletTenantConfigMapper {

    private WalletTenantConfigMapper() {}

    /**
     * Maps an entity row from {@code public.tenant_wallet_config} to the domain aggregate.
     */
    public static TenantWalletConfigDescriptor toDescriptor(WalletTenantConfigEntity entity) {
        WalletMode walletMode = WalletMode.fromValue(entity.getWalletMode());
        Optional<KeyManager> keyManager = entity.getKeyManager() != null
                ? Optional.of(KeyManager.fromValue(entity.getKeyManager()))
                : Optional.empty();

        return TenantWalletConfigDescriptor.of(
                entity.getSchemaName(),
                entity.getHost(),
                walletMode,
                keyManager,
                entity.isNaturalPersonsOnly(),
                Collections.emptyList(),
                entity.getVersion());
    }
}
