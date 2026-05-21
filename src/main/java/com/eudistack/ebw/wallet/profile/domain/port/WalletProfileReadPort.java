package com.eudistack.ebw.wallet.profile.domain.port;

import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import reactor.core.publisher.Mono;

/**
 * Output port for reading the wallet discovery profile of the current tenant.
 *
 * <p>The tenant is resolved implicitly from the Reactor {@link reactor.util.context.Context}
 * propagated by the {@code TenantAwareConnectionFactory} — callers do not pass a tenant
 * parameter. This design is consistent with every other R2DBC repository in the EBW (e.g.
 * {@code TenantConfigRepository}).
 *
 * <p>The implementing adapter ({@code R2dbcWalletProfileReadAdapter}) queries
 * {@code tenant_wallet_profile} via the schema-per-tenant connection factory. When no row
 * exists for the active tenant the returned {@code Mono} completes empty; callers are
 * responsible for interpreting that outcome (US-02 maps it to an opaque 404).
 *
 * <p>This port belongs to the domain layer; it carries zero framework imports.
 *
 * <p>See architecture.md §8.6 and technical-design.md §3.3.
 */
public interface WalletProfileReadPort {

    /**
     * Finds the wallet profile of the currently active tenant.
     *
     * @return a {@link Mono} emitting the profile when a row is found, or an empty
     *         {@link Mono} when no profile has been seeded yet (ES-02)
     */
    Mono<TenantWalletProfile> findCurrent();
}