package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.ActivationStatus;
import com.eudistack.ebw.wallet.config.domain.model.operational.DbTdeOperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfigDescriptor;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity.WalletOperationalConfigDbTdeEntity;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity.WalletOperationalConfigEntity;

import java.time.Instant;
import java.util.Optional;

/**
 * Pure static mapping between R2DBC entities and the domain aggregate
 * {@link OperationalConfigDescriptor}.
 *
 * <p>No Spring annotations — this is plain Java. Two directions are supported:
 * <ul>
 *   <li>{@link #toDescriptor} — from the pair of entities (root + sub-table) to the domain
 *       aggregate. Makes a defensive copy of {@code wrappedDek}.</li>
 *   <li>{@link #toRootEntity} / {@link #toDbTdeEntity} — from the domain aggregate to the
 *       respective entities, for INSERT/UPDATE operations. Also makes a defensive copy of
 *       {@code wrappedDek} to prevent mutation via the entity after conversion.</li>
 * </ul>
 */
public final class OperationalConfigMapper {

    private OperationalConfigMapper() {}

    /**
     * Maps the pair of entities to the domain aggregate.
     *
     * @param root      the root-table entity; must not be null
     * @param dbTde     the sub-table entity for {@code db-tde}; must not be null
     * @return the domain aggregate
     */
    public static OperationalConfigDescriptor toDescriptor(
            WalletOperationalConfigEntity root,
            WalletOperationalConfigDbTdeEntity dbTde) {
        KeyManager keyManager = KeyManager.fromValue(root.getKeyManager());
        ActivationStatus activationStatus = ActivationStatus.fromValue(root.getActivationStatus());
        Optional<Instant> connectivityVerifiedAt = Optional.ofNullable(root.getConnectivityVerifiedAt());

        // DbTdeOperationalConfig compact ctor makes a defensive copy of wrappedDek.
        DbTdeOperationalConfig operationalConfig = new DbTdeOperationalConfig(
                dbTde.getColumnEncryptionKeyArn(),
                dbTde.getWrappedDek(),    // getWrappedDek() already returns a defensive copy
                dbTde.getAlgorithm()
        );

        return new OperationalConfigDescriptor(
                root.getId(),
                keyManager,
                operationalConfig,
                root.isActive(),
                activationStatus,
                connectivityVerifiedAt,
                root.getVersion(),
                root.getUpdatedBy(),
                root.getUpdatedAt()
        );
    }

    /**
     * Maps the domain aggregate to the root-table entity.
     *
     * @param descriptor the descriptor to map; must not be null
     * @return a {@link WalletOperationalConfigEntity} ready for INSERT or UPDATE
     */
    public static WalletOperationalConfigEntity toRootEntity(OperationalConfigDescriptor descriptor) {
        WalletOperationalConfigEntity entity = new WalletOperationalConfigEntity();
        entity.setId(descriptor.id());
        entity.setKeyManager(descriptor.keyManager().getValue());
        entity.setActive(descriptor.isActive());
        entity.setActivationStatus(descriptor.activationStatus().getValue());
        entity.setConnectivityVerifiedAt(descriptor.connectivityVerifiedAt().orElse(null));
        entity.setVersion(descriptor.version());
        entity.setUpdatedBy(descriptor.updatedBy());
        entity.setUpdatedAt(descriptor.updatedAt());
        return entity;
    }

    /**
     * Maps the domain aggregate to the sub-table entity for {@code db-tde}.
     *
     * <p>Only valid when {@code descriptor.operationalConfig()} is a
     * {@link DbTdeOperationalConfig} — callers must guard this.
     *
     * @param descriptor the descriptor whose {@code operationalConfig} is a
     *                   {@link DbTdeOperationalConfig}; must not be null
     * @param configId   the UUID of the parent root row (FK); must not be null
     * @return a {@link WalletOperationalConfigDbTdeEntity} ready for INSERT or UPDATE
     * @throws IllegalArgumentException if {@code operationalConfig} is not a
     *                                  {@link DbTdeOperationalConfig}
     */
    public static WalletOperationalConfigDbTdeEntity toDbTdeEntity(
            OperationalConfigDescriptor descriptor, java.util.UUID configId) {
        if (!(descriptor.operationalConfig() instanceof DbTdeOperationalConfig db)) {
            throw new IllegalArgumentException(
                    "toDbTdeEntity called with operationalConfig type "
                            + descriptor.operationalConfig().getClass().getSimpleName()
                            + "; expected DbTdeOperationalConfig");
        }
        WalletOperationalConfigDbTdeEntity entity = new WalletOperationalConfigDbTdeEntity();
        entity.setConfigId(configId);
        entity.setColumnEncryptionKeyArn(db.columnEncryptionKeyArn());
        // db.wrappedDek() already returns a defensive copy from DbTdeOperationalConfig.
        entity.setWrappedDek(db.wrappedDek());
        entity.setAlgorithm(db.algorithm());
        entity.setCreatedAt(descriptor.updatedAt());
        return entity;
    }
}
