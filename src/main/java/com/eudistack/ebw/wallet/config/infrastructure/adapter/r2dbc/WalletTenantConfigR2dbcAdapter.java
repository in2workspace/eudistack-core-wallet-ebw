package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity.WalletTenantConfigEntity;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.mapper.WalletTenantConfigMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.data.relational.core.query.Query;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * R2DBC implementation of {@link TenantConfigurationPort}.
 *
 * <p><strong>Read path (Task 4):</strong> uses the {@code @Qualifier("publicSchema")}
 * {@link R2dbcEntityTemplate} which connects to {@code public.tenant_wallet_config}
 * via a dedicated connection pool whose {@code search_path} is permanently fixed
 * to {@code public}. This pool NEVER passes through
 * {@code TenantAwareConnectionFactoryDecorator} (AD-1, AD-S2).
 *
 * <p><strong>Write path (Task 5):</strong> uses the {@code @Qualifier("publicSchemaRw")}
 * {@link R2dbcEntityTemplate}. Performs an UPSERT with
 * {@code ON CONFLICT (schema_name) DO UPDATE} and atomically increments {@code version}.
 */
public class WalletTenantConfigR2dbcAdapter implements TenantConfigurationPort {

    private static final Logger log = LoggerFactory.getLogger(WalletTenantConfigR2dbcAdapter.class);

    /**
     * UPSERT SQL with {@code RETURNING *} so we get the post-write state
     * (including the incremented {@code version}) in a single round-trip.
     *
     * <p>Conflict is on {@code schema_name} (primary key). On insert the version is
     * always 1; on update the version is incremented atomically by the database.
     */
    private static final String UPSERT_SQL =
            "INSERT INTO public.tenant_wallet_config "
            + "  (schema_name, host, wallet_mode, key_manager, natural_persons_only, "
            + "   version, updated_by, updated_at) "
            + "VALUES "
            + "  (:schemaName, :host, :walletMode, :keyManager, :naturalPersonsOnly, "
            + "   1, :updatedBy, :updatedAt) "
            + "ON CONFLICT (schema_name) DO UPDATE SET "
            + "  host                = EXCLUDED.host, "
            + "  wallet_mode         = EXCLUDED.wallet_mode, "
            + "  key_manager         = EXCLUDED.key_manager, "
            + "  natural_persons_only = EXCLUDED.natural_persons_only, "
            + "  version             = public.tenant_wallet_config.version + 1, "
            + "  updated_by          = EXCLUDED.updated_by, "
            + "  updated_at          = EXCLUDED.updated_at "
            + "RETURNING schema_name, host, wallet_mode, key_manager, "
            + "          natural_persons_only, version";

    private final R2dbcEntityTemplate readTemplate;
    private final R2dbcEntityTemplate writeTemplate;

    /**
     * Full constructor wiring both the read-only and read-write templates.
     *
     * @param readTemplate  read-only R2DBC template backed by the {@code publicSchema} pool
     * @param writeTemplate read-write R2DBC template backed by the {@code publicSchemaRw} pool
     */
    public WalletTenantConfigR2dbcAdapter(
            R2dbcEntityTemplate readTemplate,
            R2dbcEntityTemplate writeTemplate) {
        this.readTemplate = readTemplate;
        this.writeTemplate = writeTemplate;
    }

    @Override
    public Mono<TenantWalletConfigDescriptor> findByHost(String host) {
        String normalizedHost = host.toLowerCase();
        log.debug("Looking up tenant_wallet_config for host={}", normalizedHost);
        return readTemplate
                .selectOne(
                        Query.query(Criteria.where("host").is(normalizedHost)),
                        WalletTenantConfigEntity.class)
                .map(WalletTenantConfigMapper::toDescriptor)
                .doOnSuccess(d -> {
                    if (d != null) {
                        log.debug("Found tenant_wallet_config: schemaName={}, walletMode={}",
                                d.getSchemaName(), d.getWalletMode());
                    } else {
                        log.debug("No tenant_wallet_config found for host={}", normalizedHost);
                    }
                });
    }

    /**
     * Persists a new or updated descriptor using an UPSERT that atomically increments
     * the {@code version} column on conflict (AC-3a, AC-3b).
     *
     * <p>The UPSERT is performed on the {@code publicSchemaRw} pool, which connects to
     * {@code public.tenant_wallet_config} with {@code search_path = public} (AD-S2).
     *
     * @param descriptor the descriptor to persist; caller is responsible for invariant
     *                   validation before calling this method
     * @return a {@link Mono} emitting the persisted descriptor (with the version returned
     *         by the database after the UPSERT)
     */
    @Override
    public Mono<TenantWalletConfigDescriptor> save(TenantWalletConfigDescriptor descriptor) {
        String keyManagerValue = descriptor.getKeyManager()
                .map(km -> km.getValue())
                .orElse(null);

        log.debug("Upserting tenant_wallet_config: schemaName={}, walletMode={}",
                descriptor.getSchemaName(), descriptor.getWalletMode());

        DatabaseClient dbClient = writeTemplate.getDatabaseClient();
        DatabaseClient.GenericExecuteSpec spec = dbClient.sql(UPSERT_SQL)
                .bind("schemaName", descriptor.getSchemaName())
                .bind("host", descriptor.getHost())
                .bind("walletMode", descriptor.getWalletMode().getValue())
                .bind("naturalPersonsOnly", descriptor.isNaturalPersonsOnly())
                .bind("updatedBy", "system")
                .bind("updatedAt", Instant.now());

        if (keyManagerValue != null) {
            spec = spec.bind("keyManager", keyManagerValue);
        } else {
            spec = spec.bindNull("keyManager", String.class);
        }

        return spec.map((row, metadata) -> {
            WalletTenantConfigEntity entity = new WalletTenantConfigEntity();
            entity.setSchemaName(row.get("schema_name", String.class));
            entity.setHost(row.get("host", String.class));
            entity.setWalletMode(row.get("wallet_mode", String.class));
            entity.setKeyManager(row.get("key_manager", String.class));
            Boolean npo = row.get("natural_persons_only", Boolean.class);
            entity.setNaturalPersonsOnly(Boolean.TRUE.equals(npo));
            Long version = row.get("version", Long.class);
            entity.setVersion(version != null ? version : 1L);
            return WalletTenantConfigMapper.toDescriptor(entity);
        })
        .one()
        .doOnSuccess(saved -> log.info(
                "Upserted tenant_wallet_config: schemaName={}, walletMode={}, version={}",
                saved.getSchemaName(), saved.getWalletMode(), saved.getVersion()));
    }
}
