package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity.WalletTenantConfigEntity;

import java.util.Collections;
import java.util.Optional;

/**
 * Bidirectional mapper between {@link WalletTenantConfigEntity} and
 * {@link TenantWalletConfigDescriptor}.
 *
 * <p>Pure static utility — no Spring, no I/O.
 *
 * <p>{@code supportedCredentials} is not persisted in the entity in this Story (US-01);
 * the mapper always returns an empty list on read and ignores it on write.
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

    /**
     * Maps the domain aggregate to a persistable entity.
     *
     * <p>The {@code updatedBy} and {@code updatedAt} fields are set by the caller
     * (the adapter write path) based on the command context. On a pure read path,
     * this method is not invoked.
     */
    public static WalletTenantConfigEntity toEntity(TenantWalletConfigDescriptor descriptor) {
        WalletTenantConfigEntity entity = new WalletTenantConfigEntity();
        entity.setSchemaName(descriptor.getSchemaName());
        entity.setHost(descriptor.getHost());
        entity.setWalletMode(descriptor.getWalletMode().getValue());
        entity.setKeyManager(descriptor.getKeyManager()
                .map(KeyManager::getValue)
                .orElse(null));
        entity.setNaturalPersonsOnly(descriptor.isNaturalPersonsOnly());
        entity.setVersion(descriptor.getVersion());
        return entity;
    }
}
