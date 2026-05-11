package com.eudistack.ebw.wallet.config.domain.port;

import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import reactor.core.publisher.Mono;

/**
 * Output port — persistence contract for {@link TenantWalletConfigDescriptor}.
 *
 * <p>Read path ({@link #findByHost}) targets the {@code public.tenant_wallet_config} table
 * via a read-only connection pool {@code @Qualifier("publicSchema")}.
 *
 * <p>Write path ({@link #save}) targets the same table via a read-write connection pool
 * {@code @Qualifier("publicSchemaRw")} and performs an UPSERT with optimistic-lock version bump.
 *
 * <p>This interface has zero framework or Spring imports — it belongs to the domain layer.
 * The implementing adapter lives in {@code infrastructure/persistence}.
 */
public interface TenantConfigurationPort {

    /**
     * Looks up a tenant's wallet configuration by its public hostname.
     *
     * <p>The host is expected to be already normalized to lowercase by the caller before
     * this method is invoked (per the normalisation policy in AC-1d).
     *
     * @param host the tenant hostname (e.g. {@code acme.eudiw.example.com})
     * @return a {@link Mono} emitting the descriptor, or an empty {@link Mono} if not found
     */
    Mono<TenantWalletConfigDescriptor> findByHost(String host);

    /**
     * Looks up a tenant's wallet configuration by its schema name (the aggregate key).
     *
     * <p>Used by the write path to fetch the "before image" so the audit trail can record the
     * actual from/to deltas (AC-3a / AC-3b / FR-30) and to distinguish create vs update.
     *
     * @param schemaName the tenant schema name (validated PostgreSQL identifier)
     * @return a {@link Mono} emitting the descriptor, or an empty {@link Mono} if the tenant has
     *         no configuration yet
     */
    Mono<TenantWalletConfigDescriptor> findBySchemaName(String schemaName);

    /**
     * Persists a new or updated {@link TenantWalletConfigDescriptor}.
     *
     * <p>The adapter performs an UPSERT ({@code ON CONFLICT (schema_name) DO UPDATE}) and
     * increments the {@code version} column atomically. The returned descriptor reflects the
     * version stored in the database after the operation.
     *
     * <p>When {@code expectedVersion} is non-null AND the row already exists, the update is
     * conditional on {@code version = expectedVersion}; if it does not match, the {@link Mono}
     * errors with {@code ConfigVersionConflictException} (→ HTTP 409). On an INSERT (new row)
     * there is no version to check and {@code expectedVersion} is ignored.
     *
     * @param descriptor      the descriptor to persist; must have passed invariant validation
     * @param expectedVersion the optimistic-lock version, or {@code null} for an unconditional
     *                        create/update
     * @return a {@link Mono} emitting the persisted descriptor (with updated {@code version})
     */
    Mono<TenantWalletConfigDescriptor> save(TenantWalletConfigDescriptor descriptor, Long expectedVersion);
}
