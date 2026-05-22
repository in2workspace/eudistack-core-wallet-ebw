package com.eudistack.ebw.wallet.profile.domain.port;

import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import reactor.core.publisher.Mono;

/**
 * Input port for querying the wallet discovery profile of the current tenant.
 *
 * <p>The tenant is resolved implicitly from the Reactor {@link reactor.util.context.Context}
 * — callers do not pass a tenant parameter. The implementing use case
 * ({@code ReadWalletProfileUseCase}) reads {@code TENANT_DOMAIN} from the context and
 * delegates to the output port {@link WalletProfileReadPort}.
 *
 * <p>When the tenant cannot be resolved (absent from context, host malformed) or when no
 * profile row has been seeded, the returned {@link Mono} completes with a
 * {@link com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException}
 * (opaque 404 — anti-enumeration, AD-413-2).
 *
 * <p>This port belongs to the domain layer and carries zero framework imports.
 *
 * <p>See architecture.md §5.2.1 and technical-design.md §3.3.
 */
public interface WalletProfileQueryPort {

    /**
     * Queries the wallet discovery profile of the currently active tenant.
     *
     * @return a {@link Mono} emitting the profile on success; an error signal with
     *         {@link com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException}
     *         when the tenant is absent from the Reactor Context or when no profile row exists
     */
    Mono<TenantWalletProfile> queryByCurrentTenant();
}
