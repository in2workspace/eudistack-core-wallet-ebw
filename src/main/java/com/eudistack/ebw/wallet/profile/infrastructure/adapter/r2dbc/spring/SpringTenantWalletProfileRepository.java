package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc.entity.TenantWalletProfileEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Spring Data R2DBC repository for {@link TenantWalletProfileEntity}.
 *
 * <p>The table {@code tenant_wallet_profile} has at most one row per tenant schema
 * (enforced by the {@code pk_tenant_wallet_profile} primary key on the {@code tenant}
 * column). Schema selection is transparent — it is handled by the existing
 * {@code TenantAwareConnectionFactory} (provisioned by EUDISTACK-480) via Reactor
 * Context, so callers of this repository do not pass a tenant parameter.
 *
 * <p>{@link #findFirstBy()} issues {@code SELECT … FROM tenant_wallet_profile LIMIT 1}
 * against whichever schema the current Reactor Context has established. The result is
 * {@link Mono#empty()} when no row exists for the current tenant (ES-02 in
 * {@code acceptance-criteria.md}) — Spring Data R2DBC returns empty naturally for
 * a query that matches no rows.
 */
public interface SpringTenantWalletProfileRepository
        extends ReactiveCrudRepository<TenantWalletProfileEntity, String> {

    /**
     * Retrieves the single wallet-profile row for the current tenant schema.
     *
     * <p>Returns {@link Mono#empty()} when no row is present (tenant not yet seeded).
     * The adapter {@code R2dbcWalletProfileReadAdapter} propagates this empty signal
     * upstream to its caller (AC-07, ES-02).
     *
     * @return a {@link Mono} emitting the entity, or empty if no row exists
     */
    Mono<TenantWalletProfileEntity> findFirstBy();
}