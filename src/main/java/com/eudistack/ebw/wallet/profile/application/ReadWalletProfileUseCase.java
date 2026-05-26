package com.eudistack.ebw.wallet.profile.application;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException.Reason;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileReadPort;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Application service implementing {@link WalletProfileQueryPort}.
 *
 * <p>Reads the {@code TENANT_DOMAIN} key from the Reactor Context (set by
 * {@code TenantDomainWebFilter}) and delegates to the output port
 * {@link WalletProfileReadPort#findCurrent()} to retrieve the profile row.
 *
 * <p>Error semantics (AD-413-2 — byte-exact anti-enumeration):
 * <ul>
 *   <li>Context has no {@code TENANT_DOMAIN} key → emits
 *       {@code TenantUnknownException(TENANT_ABSENT_FROM_CONTEXT)}.
 *   <li>Port returns {@code Mono.empty()} (no profile seeded) → emits
 *       {@code TenantUnknownException(PROFILE_NOT_SEEDED)}.
 *   <li>R2DBC errors ({@link io.r2dbc.spi.R2dbcException} and subclasses) → propagated
 *       without capturing; the exception handler maps them to 503 (ES-04/ES-05).
 * </ul>
 *
 * <p>See technical-design.md §3.2 and §3.5 AD-413-1, acceptance-criteria.md AC-04/AC-08.
 */
@Service
public class ReadWalletProfileUseCase implements WalletProfileQueryPort {

    private final WalletProfileReadPort walletProfileReadPort;

    public ReadWalletProfileUseCase(WalletProfileReadPort walletProfileReadPort) {
        this.walletProfileReadPort = walletProfileReadPort;
    }

    @Override
    public Mono<TenantWalletProfile> queryByCurrentTenant() {
        return Mono.deferContextual(ctx -> {
            if (!ctx.hasKey(ReactorContextKeys.TENANT_DOMAIN)) {
                return Mono.error(new TenantUnknownException(Reason.TENANT_ABSENT_FROM_CONTEXT));
            }
            return walletProfileReadPort.findCurrent()
                    .switchIfEmpty(Mono.error(
                            new TenantUnknownException(Reason.PROFILE_NOT_SEEDED)));
        });
    }
}
