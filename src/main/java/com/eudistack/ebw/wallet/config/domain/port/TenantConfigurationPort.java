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
     * Persists a new or updated {@link TenantWalletConfigDescriptor}.
     *
     * <p>The adapter performs an UPSERT ({@code ON CONFLICT (schema_name) DO UPDATE}) and
     * increments the {@code version} column atomically. The returned descriptor reflects the
     * version stored in the database after the operation.
     *
     * @param descriptor the descriptor to persist; must have passed invariant validation
     * @return a {@link Mono} emitting the persisted descriptor (with updated {@code version})
     */
    Mono<TenantWalletConfigDescriptor> save(TenantWalletConfigDescriptor descriptor);
}
