package com.eudistack.ebw.wallet.config.domain.port;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfigDescriptor;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Output port — read and write persistence contract for the operational configuration plane.
 *
 * <p>The operational-config plane persists key-manager-specific parameters in a pair of tables:
 * the root table {@code wallet_operational_config} (one row per {@code key_manager}) and a
 * subtype sub-table (e.g. {@code wallet_operational_config_db_tde}). Both tables live exclusively
 * in the tenant-scoped schema ({@code <tenant>_business_wallet}), resolved at runtime by the
 * {@code TenantAwareConnectionFactoryDecorator}. This port has zero framework or infrastructure
 * imports — it belongs to the domain layer.
 *
 * <h2>Dual-read semantics</h2>
 * {@link #findActive()} returns {@code Mono<Optional<OperationalConfigDescriptor>>} intentionally.
 * The two states have distinct operational meanings:
 * <ul>
 *   <li><b>{@code Optional.empty()}</b> — the tenant has not yet applied an operational
 *       configuration (common during initial setup or before US-03 runs). The caller must handle
 *       this as "not yet configured" and may return a {@code 404} or trigger a setup flow.</li>
 *   <li><b>{@code Optional.of(descriptor)}</b> — the tenant has an active descriptor and the
 *       system is ready to use it for column-encryption or further verification.</li>
 * </ul>
 * Collapsing this to {@code Mono.empty()} would lose the ability to distinguish
 * "not configured" from a transient read error; it would also break reactive operators that
 * rely on presence/absence semantics ({@code switchIfEmpty} vs {@code defaultIfEmpty}).
 *
 * <p>The implementing adapter is {@code OperationalConfigR2dbcAdapter}. This port is consumed by:
 * <ul>
 *   <li>{@code OperationalConfigWriter} (write path — US-03)</li>
 *   <li>{@code OperationalConfigReader} (read path — US-03; US-08 health)</li>
 *   <li>{@code DbTdeProbeAdapter} (via {@link #canQuerySubtable} — connectivity probe)</li>
 * </ul>
 */
public interface OperationalConfigPort {

    /**
     * Finds the currently active operational configuration descriptor for the current tenant.
     *
     * <p>The tenant is resolved from the reactive context (via
     * {@code Mono.deferContextual} in the adapter) — no explicit tenant parameter is needed.
     *
     * <p>Returns {@code Optional.empty()} if no configuration with {@code is_active=true} exists
     * for the tenant. Never returns {@code Mono.empty()}: a missing configuration is represented
     * as a present {@code Optional.empty()}, not a missing reactor signal.
     *
     * @return a {@link Mono} emitting an {@link Optional} wrapping the active descriptor,
     *         or {@link Optional#empty()} if no active configuration exists
     */
    Mono<Optional<OperationalConfigDescriptor>> findActive();

    /**
     * Atomically persists (inserts or updates) the root row and the appropriate sub-table row
     * for the given descriptor.
     *
     * <p>Uses an optimistic lock: the adapter checks the {@code version} field on update
     * ({@code UPDATE ... WHERE id = ? AND version = ?}) and increments it on success.
     * If the row was concurrently modified and the version no longer matches,
     * the adapter throws {@code OptimisticLockingFailureException} (Spring Data R2DBC), which
     * the writer maps to a {@code 412 Precondition Failed} response.
     *
     * <p>This method must be called within the transaction managed by
     * {@code OperationalConfigWriter} (via {@code TransactionalOperator.execute}).
     *
     * @param descriptor the descriptor to persist; its {@code version} field determines whether
     *                   this is an initial insert ({@code version == 0}) or an update
     * @return a {@link Mono} emitting the persisted descriptor with the updated {@code version}
     *         and {@code updatedAt} fields
     */
    Mono<OperationalConfigDescriptor> upsert(OperationalConfigDescriptor descriptor);

    /**
     * Verifies that the sub-table for the given {@code keyManager} exists in the current tenant's
     * schema and is accessible.
     *
     * <p>Used by {@code DbTdeProbeAdapter} as a defense-in-depth check: if the
     * {@code db/tenant/V4} migration was not applied for the tenant, this returns {@code false}
     * and the probe fails with {@code ProbeResult.Failed("subtable not found")}.
     *
     * <p>Implementation: {@code SELECT 1 FROM wallet_operational_config_db_tde LIMIT 1} (for
     * {@code DB_TDE}); the query runs against the tenant-scoped schema.
     *
     * @param keyManager the key-manager variant whose sub-table is to be queried
     * @return a {@link Mono} emitting {@code true} if the sub-table exists and is accessible,
     *         or {@code false} otherwise
     */
    Mono<Boolean> canQuerySubtable(KeyManager keyManager);
}
