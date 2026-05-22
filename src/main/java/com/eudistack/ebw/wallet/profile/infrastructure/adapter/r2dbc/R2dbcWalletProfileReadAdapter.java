package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileReadPort;
import com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc.spring.SpringTenantWalletProfileRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

/**
 * R2DBC adapter implementing {@link WalletProfileReadPort}.
 *
 * <p>Delegates to {@link SpringTenantWalletProfileRepository#findFirstBy()}, which issues a
 * {@code SELECT … FROM tenant_wallet_profile LIMIT 1} against the schema resolved by the
 * existing {@code TenantAwareConnectionFactory} from Reactor Context (EUDISTACK-480). No
 * tenant-selection logic lives here — the connection factory handles it transparently.
 *
 * <p><b>Mapping (AD-412-3):</b> The entity-to-record conversion is done inline without a
 * separate mapper class, consistent with {@code TenantConfigR2dbcRepository}. The five
 * columns map directly: {@code tenant}, {@code wallet_mode} → {@link WalletMode#fromDbValue},
 * {@code key_manager} → {@link KeyManager#fromDbValue} (returns {@code null} for
 * browser-mode rows), {@code created_at}, and {@code updated_at}.
 *
 * <p><b>Empty signal (ES-02):</b> When no row exists for the current tenant schema,
 * {@code findFirstBy()} returns {@link Mono#empty()}. This adapter propagates that signal
 * unchanged — it does NOT convert it to an error. The caller (future
 * {@code ReadWalletProfileUseCase} in US-02) decides how to handle absence.
 *
 * <p><b>Error propagation (ES-04, ES-05):</b> R2DBC driver errors (connection refused,
 * statement timeout) are not caught or translated here. They propagate to the caller as
 * typed {@link io.r2dbc.spi.R2dbcException} subclasses, consistent with
 * architecture.md §8.7 (error-handling responsibility belongs to the use-case layer).
 *
 * <p>See technical-design.md §3.3 (port/adapter table) and §3.4 (sequence diagram).
 */
@Repository
public class R2dbcWalletProfileReadAdapter implements WalletProfileReadPort {

    private final SpringTenantWalletProfileRepository repository;

    public R2dbcWalletProfileReadAdapter(SpringTenantWalletProfileRepository repository) {
        this.repository = repository;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Maps the raw entity to the domain record inline. Returns {@link Mono#empty()}
     * when no row exists for the current tenant schema (ES-02).
     */
    @Override
    public Mono<TenantWalletProfile> findCurrent() {
        return repository.findFirstBy()
                .map(e -> new TenantWalletProfile(
                        e.getTenant(),
                        WalletMode.fromDbValue(e.getWalletMode()),
                        KeyManager.fromDbValue(e.getKeyManager()),
                        e.getCreatedAt(),
                        e.getUpdatedAt()
                ));
    }
}