package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc.entity.TenantWalletProfileEntity;
import org.springframework.data.repository.Repository;
import reactor.core.publisher.Mono;

/**
 * Read-only Spring Data R2DBC repository for {@link TenantWalletProfileEntity} (D-001).
 *
 * <p>Extends the marker {@link Repository} interface (not {@code ReactiveCrudRepository})
 * so only the declared {@link #findFirstBy()} method is exposed — write operations are
 * not accessible from Java code, matching the operator-only write contract.
 *
 * <p>Schema selection is transparent — handled by {@code TenantAwareConnectionFactory}
 * (EUDISTACK-480) via Reactor Context; callers do not pass a tenant parameter.
 *
 * <p>{@link #findFirstBy()} issues {@code SELECT … FROM tenant_wallet_profile LIMIT 1}
 * against the current tenant schema. Returns {@link Mono#empty()} when no row exists
 * (ES-02) — Spring Data R2DBC produces empty naturally for a zero-row result.
 */
public interface SpringTenantWalletProfileRepository
        extends Repository<TenantWalletProfileEntity, String> {

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