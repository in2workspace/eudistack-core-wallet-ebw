package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.port.OperationalConfigPort;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity.WalletOperationalConfigDbTdeEntity;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity.WalletOperationalConfigEntity;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.mapper.OperationalConfigMapper;
import io.r2dbc.spi.R2dbcException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * R2DBC implementation of {@link OperationalConfigPort} for the operational configuration plane.
 *
 * <p>Uses the default {@link DatabaseClient} bean, which is backed by the primary
 * {@code ConnectionFactory} decorated by {@code TenantAwareConnectionFactoryDecorator}.
 * That decorator sets {@code search_path} to the current tenant's schema on each
 * connection acquisition, so all queries in this adapter operate against
 * {@code <tenant>_business_wallet.wallet_operational_config[_db_tde]} (AD-1).
 *
 * <p>This adapter does <strong>not</strong> use the {@code @Qualifier("publicSchema")}
 * connection factory — the operational plane is strictly per-tenant (AD-1, AC-3a).
 *
 * <p>This adapter does <strong>not</strong> open its own transaction. The caller
 * ({@code OperationalConfigWriter}) wraps calls in {@code TransactionalOperator.execute},
 * and the reactive transaction propagates through the Reactor context.
 *
 * <p>This class is NOT annotated with {@code @Component}. It is instantiated by
 * {@code OperationalConfigBeans} (Task 9) following the explicit-wiring pattern established
 * by {@code WalletTenantConfigR2dbcAdapter}.
 */
public class OperationalConfigR2dbcAdapter implements OperationalConfigPort {

    private static final Logger log = LoggerFactory.getLogger(OperationalConfigR2dbcAdapter.class);

    private static final String FIND_ACTIVE_SQL =
            "SELECT woc.id          AS woc_id, "
            + "woc.key_manager       AS woc_key_manager, "
            + "woc.is_active         AS woc_is_active, "
            + "woc.activation_status AS woc_activation_status, "
            + "woc.connectivity_verified_at AS woc_connectivity_verified_at, "
            + "woc.version           AS woc_version, "
            + "woc.updated_by        AS woc_updated_by, "
            + "woc.updated_at        AS woc_updated_at, "
            + "woctde.config_id      AS tde_config_id, "
            + "woctde.column_encryption_key_arn AS tde_column_encryption_key_arn, "
            + "woctde.wrapped_dek    AS tde_wrapped_dek, "
            + "woctde.algorithm      AS tde_algorithm, "
            + "woctde.created_at     AS tde_created_at "
            + "FROM wallet_operational_config woc "
            + "LEFT JOIN wallet_operational_config_db_tde woctde "
            + "  ON woctde.config_id = woc.id "
            + "WHERE woc.is_active = true";

    private static final String INSERT_ROOT_SQL =
            "INSERT INTO wallet_operational_config "
            + "(id, key_manager, is_active, activation_status, connectivity_verified_at, "
            + " version, updated_by, updated_at) "
            + "VALUES (:id, :keyManager, :isActive, :activationStatus, "
            + "        :connectivityVerifiedAt, :version, :updatedBy, :updatedAt)";

    private static final String INSERT_DB_TDE_SQL =
            "INSERT INTO wallet_operational_config_db_tde "
            + "(config_id, column_encryption_key_arn, wrapped_dek, algorithm, created_at) "
            + "VALUES (:configId, :columnEncryptionKeyArn, :wrappedDek, :algorithm, :createdAt)";

    private static final String UPDATE_ROOT_SQL =
            "UPDATE wallet_operational_config "
            + "SET is_active = :isActive, "
            + "    activation_status = :activationStatus, "
            + "    connectivity_verified_at = :connectivityVerifiedAt, "
            + "    version = :newVersion, "
            + "    updated_by = :updatedBy, "
            + "    updated_at = :updatedAt "
            + "WHERE id = :id AND version = :expectedVersion";

    private static final String UPDATE_DB_TDE_SQL =
            "UPDATE wallet_operational_config_db_tde "
            + "SET column_encryption_key_arn = :columnEncryptionKeyArn, "
            + "    wrapped_dek = :wrappedDek, "
            + "    algorithm = :algorithm "
            + "WHERE config_id = :configId";

    private static final String SELECT_ACTIVE_ID_SQL =
            "SELECT id FROM wallet_operational_config WHERE is_active = true LIMIT 1";

    private static final String PROBE_DB_TDE_SQL =
            "SELECT 1 FROM wallet_operational_config_db_tde LIMIT 1";

    private final DatabaseClient databaseClient;

    /**
     * Constructs the adapter using the default (tenant-aware) {@link DatabaseClient}.
     *
     * @param databaseClient the auto-configured client; its underlying {@code ConnectionFactory}
     *                       must be the {@code TenantAwareConnectionFactoryDecorator}-wrapped one
     */
    public OperationalConfigR2dbcAdapter(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    /**
     * Returns the active operational configuration descriptor for the current tenant, or
     * {@link Optional#empty()} if none exists.
     *
     * <p>Executes a single JOIN query against {@code wallet_operational_config} and
     * {@code wallet_operational_config_db_tde} where {@code is_active = true}.
     */
    @Override
    public Mono<Optional<OperationalConfigDescriptor>> findActive() {
        return databaseClient.sql(FIND_ACTIVE_SQL)
                .map(row -> {
                    WalletOperationalConfigEntity root = new WalletOperationalConfigEntity();
                    root.setId(row.get("woc_id", UUID.class));
                    root.setKeyManager(row.get("woc_key_manager", String.class));
                    root.setActive(Boolean.TRUE.equals(row.get("woc_is_active", Boolean.class)));
                    root.setActivationStatus(row.get("woc_activation_status", String.class));
                    root.setConnectivityVerifiedAt(row.get("woc_connectivity_verified_at", Instant.class));
                    root.setVersion(longValue(row.get("woc_version", Number.class)));
                    root.setUpdatedBy(row.get("woc_updated_by", String.class));
                    root.setUpdatedAt(row.get("woc_updated_at", Instant.class));

                    WalletOperationalConfigDbTdeEntity dbTde = new WalletOperationalConfigDbTdeEntity();
                    dbTde.setConfigId(row.get("tde_config_id", UUID.class));
                    dbTde.setColumnEncryptionKeyArn(row.get("tde_column_encryption_key_arn", String.class));
                    dbTde.setWrappedDek(row.get("tde_wrapped_dek", byte[].class));
                    dbTde.setAlgorithm(row.get("tde_algorithm", String.class));
                    dbTde.setCreatedAt(row.get("tde_created_at", Instant.class));

                    return OperationalConfigMapper.toDescriptor(root, dbTde);
                })
                .one()
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .doOnSuccess(opt -> {
                    if (opt.isEmpty()) {
                        log.debug("findActive: no active operational config found for current tenant");
                    } else {
                        log.debug("findActive: found active operational config with keyManager={}",
                                opt.get().keyManager());
                    }
                });
    }

    /**
     * Atomically persists (inserts or updates) the root row and the appropriate sub-table row.
     *
     * <p>Branch logic based on {@code descriptor.version()}:
     * <ul>
     *   <li>{@code version == 0} — INSERT path: inserts the root row and the sub-table row
     *       using the {@code id} from the descriptor.</li>
     *   <li>{@code version > 0} — UPDATE path: first resolves the existing {@code id} via
     *       {@code SELECT id FROM wallet_operational_config WHERE is_active = true}, then
     *       updates both rows using an optimistic lock condition
     *       ({@code WHERE id = ? AND version = ?}). If no row is updated (version mismatch
     *       or concurrent modification), throws {@link OptimisticLockingFailureException}.</li>
     * </ul>
     *
     * <p>This method must be invoked within a transaction managed by the caller
     * ({@code TransactionalOperator.execute}).
     */
    @Override
    public Mono<OperationalConfigDescriptor> upsert(OperationalConfigDescriptor descriptor) {
        if (descriptor.version() == 0) {
            return insertRootAndSubTable(descriptor);
        }
        return updateRootAndSubTable(descriptor);
    }

    /**
     * Verifies that the sub-table for {@link KeyManager#DB_TDE} exists and is accessible
     * in the current tenant's schema.
     *
     * <p>Executes {@code SELECT 1 FROM wallet_operational_config_db_tde LIMIT 1}.
     * Returns {@code true} on success (whether the table has rows or is empty — the query
     * completing without error is sufficient proof the table exists); returns {@code false}
     * if an {@link R2dbcException} is thrown — the probe caller treats {@code false} as a
     * reason to emit {@code ProbeResult.Failed("subtable not found")}.
     */
    @Override
    public Mono<Boolean> canQuerySubtable(KeyManager keyManager) {
        if (keyManager != KeyManager.DB_TDE) {
            // Only DB_TDE sub-table is created in this Story — others return false immediately.
            log.debug("canQuerySubtable: keyManager={} has no sub-table in US-03 — returning false",
                    keyManager);
            return Mono.just(false);
        }
        return databaseClient.sql(PROBE_DB_TDE_SQL)
                .fetch()
                .all()
                .collectList()
                .map(rows -> true)          // query completed without error → table exists
                .defaultIfEmpty(true)       // 0 rows is also OK — table exists but is empty
                .onErrorResume(ex -> {
                    if (ex instanceof R2dbcException r2dbcEx) {
                        log.debug("canQuerySubtable: R2DBC exception probing db-tde sub-table — {}",
                                r2dbcEx.getMessage());
                    } else {
                        log.debug("canQuerySubtable: unexpected exception probing db-tde sub-table — {}",
                                ex.getClass().getSimpleName());
                    }
                    return Mono.just(false);
                });
    }

    // --- Private helpers ---

    private Mono<OperationalConfigDescriptor> insertRootAndSubTable(OperationalConfigDescriptor descriptor) {
        WalletOperationalConfigEntity rootEntity = OperationalConfigMapper.toRootEntity(descriptor);
        WalletOperationalConfigDbTdeEntity dbTdeEntity =
                OperationalConfigMapper.toDbTdeEntity(descriptor, descriptor.id());

        DatabaseClient.GenericExecuteSpec insertRootSpec = databaseClient.sql(INSERT_ROOT_SQL)
                .bind("id", rootEntity.getId())
                .bind("keyManager", rootEntity.getKeyManager())
                .bind("isActive", rootEntity.isActive())
                .bind("activationStatus", rootEntity.getActivationStatus())
                .bind("version", rootEntity.getVersion())
                .bind("updatedBy", rootEntity.getUpdatedBy())
                .bind("updatedAt", rootEntity.getUpdatedAt());
        // connectivity_verified_at is nullable (NULL when activation_status = 'pending-spi').
        insertRootSpec = rootEntity.getConnectivityVerifiedAt() != null
                ? insertRootSpec.bind("connectivityVerifiedAt", rootEntity.getConnectivityVerifiedAt())
                : insertRootSpec.bindNull("connectivityVerifiedAt", Instant.class);

        final DatabaseClient.GenericExecuteSpec finalInsertRootSpec = insertRootSpec;
        return finalInsertRootSpec
                .fetch()
                .rowsUpdated()
                .flatMap(count -> databaseClient.sql(INSERT_DB_TDE_SQL)
                        .bind("configId", dbTdeEntity.getConfigId())
                        .bind("columnEncryptionKeyArn", dbTdeEntity.getColumnEncryptionKeyArn())
                        .bind("wrappedDek", dbTdeEntity.getWrappedDek())
                        .bind("algorithm", dbTdeEntity.getAlgorithm())
                        .bind("createdAt", dbTdeEntity.getCreatedAt())
                        .fetch()
                        .rowsUpdated())
                .thenReturn(descriptor)
                .doOnSuccess(d -> log.debug("upsert (INSERT): persisted operational config id={}", d.id()));
    }

    private Mono<OperationalConfigDescriptor> updateRootAndSubTable(OperationalConfigDescriptor descriptor) {
        // Resolve the existing id from the active row — the descriptor's id is the new UUID
        // assigned by the writer; on UPDATE the actual row id was assigned on the original INSERT.
        return databaseClient.sql(SELECT_ACTIVE_ID_SQL)
                .map(row -> row.get("id", UUID.class))
                .one()
                .flatMap(existingId -> {
                    long expectedVersion = descriptor.version() - 1;
                    WalletOperationalConfigEntity rootEntity = OperationalConfigMapper.toRootEntity(descriptor);

                    DatabaseClient.GenericExecuteSpec updateRootSpec = databaseClient.sql(UPDATE_ROOT_SQL)
                            .bind("isActive", rootEntity.isActive())
                            .bind("activationStatus", rootEntity.getActivationStatus())
                            .bind("newVersion", rootEntity.getVersion())
                            .bind("updatedBy", rootEntity.getUpdatedBy())
                            .bind("updatedAt", rootEntity.getUpdatedAt())
                            .bind("id", existingId)
                            .bind("expectedVersion", expectedVersion);
                    // connectivity_verified_at is nullable.
                    updateRootSpec = rootEntity.getConnectivityVerifiedAt() != null
                            ? updateRootSpec.bind("connectivityVerifiedAt",
                                    rootEntity.getConnectivityVerifiedAt())
                            : updateRootSpec.bindNull("connectivityVerifiedAt", Instant.class);

                    final DatabaseClient.GenericExecuteSpec finalUpdateRootSpec = updateRootSpec;
                    return finalUpdateRootSpec
                            .fetch()
                            .rowsUpdated()
                            .flatMap(updatedRows -> {
                                if (updatedRows == 0) {
                                    log.warn("Optimistic lock failure: existingId={}, expectedVersion={}",
                                            existingId, expectedVersion);
                                    return Mono.<OperationalConfigDescriptor>error(
                                            new OptimisticLockingFailureException(
                                                    "wallet_operational_config row with id=" + existingId
                                                            + " was modified concurrently; expected version="
                                                            + expectedVersion));
                                }
                                WalletOperationalConfigDbTdeEntity dbTdeEntity =
                                        OperationalConfigMapper.toDbTdeEntity(descriptor, existingId);
                                return databaseClient.sql(UPDATE_DB_TDE_SQL)
                                        .bind("columnEncryptionKeyArn", dbTdeEntity.getColumnEncryptionKeyArn())
                                        .bind("wrappedDek", dbTdeEntity.getWrappedDek())
                                        .bind("algorithm", dbTdeEntity.getAlgorithm())
                                        .bind("configId", existingId)
                                        .fetch()
                                        .rowsUpdated()
                                        .thenReturn(descriptor);
                            })
                            .doOnSuccess(d -> log.debug(
                                    "upsert (UPDATE): updated operational config existingId={}", existingId));
                })
                .switchIfEmpty(Mono.error(new OptimisticLockingFailureException(
                        "No active operational config row found for UPDATE — concurrent delete or "
                                + "first-write race; expected is_active=true row to exist")));
    }

    private static long longValue(Number number) {
        return number == null ? 0L : number.longValue();
    }
}
