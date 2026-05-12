package com.eudistack.ebw.wallet.config.domain.port;

import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import reactor.core.publisher.Mono;

/**
 * Output port — read-only persistence contract for {@link TenantWalletConfigDescriptor}.
 *
 * <p>The read path ({@link #findByHost}) targets the {@code public.tenant_wallet_config} table
 * via a read-only connection pool {@code @Qualifier("publicSchema")}.
 *
 * <p>The write path (admin endpoint, single transactional writer, optimistic lock, audit,
 * targeted CloudFront invalidation) is out of scope for EUDISTACK-412 — it moved to EUDISTACK-55.
 * In this Story the discovery plane is seeded via SQL; the table's CHECK constraints are the only
 * guard against an inconsistent {@code wallet_mode}/{@code key_manager} pairing.
 *
 * <p>This interface has zero framework or Spring imports — it belongs to the domain layer.
 * The implementing adapter lives in {@code infrastructure/adapter/r2dbc}.
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
}
