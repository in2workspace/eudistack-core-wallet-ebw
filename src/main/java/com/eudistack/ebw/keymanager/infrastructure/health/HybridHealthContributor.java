package com.eudistack.ebw.keymanager.infrastructure.health;

import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import com.eudistack.ebw.keymanager.infrastructure.observability.HybridKeyManagerTelemetry;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Reactive health indicator for the hybrid key-manager adapter (US-09 / EUDISTACK-541).
 *
 * <p>Hybrid mode is a per-tenant attribute ({@code tenant_wallet_profile.key_manager}), not
 * an instance-wide deployment flag — the same running instance serves hybrid tenants and
 * db/browser tenants side by side (see {@link com.eudistack.ebw.keymanager.application.KeyManagerResolver},
 * which resolves the adapter per-request the same way). This indicator therefore resolves the
 * tenant of the <em>current</em> {@code /health} request via {@link WalletProfileQueryPort} and
 * only runs the hybrid checks below when that tenant's key manager is {@link KeyManager#HYBRID}.
 * For any other tenant — or when the tenant cannot be resolved at all (no Host header, no
 * profile row) — it reports a neutral UP with an explanatory note instead of a misleading DOWN.
 *
 * <p>Always registered (no {@code @ConditionalOnProperty} gate), matching every other
 * hybrid-related bean in {@code KeyManagerConfiguration} — there is no global "this deployment
 * is hybrid" switch anywhere else in this codebase.
 *
 * <p>When the resolved tenant is hybrid, exposes three operational indicators (architecture.md §5.4):
 * <ol>
 *   <li>{@code prf_gate_pass_rate} — ratio of onboardings that passed the PRF gate over total
 *       attempts. Threshold: ≥ 0.75 → UP, < 0.75 → DOWN. Read from Micrometer counters
 *       {@code hybrid.prf_gate.passes.total} and {@code hybrid.prf_gate.attempts.total};
 *       no DB query is performed for this indicator.
 *   <li>{@code wrap_handles_total} — count of rows in {@code hybrid_wrapped_key_handle}.
 *       Informational; does not affect the global status.
 *   <li>{@code salt_coherent} — every {@code hybrid_wrapped_key_handle} row has a matching
 *       {@code hybrid_prf_salt} row for the same {@code (holder_id, credential_id)}. The
 *       {@code fk_hwkh_prf_salt} foreign key (V4 tenant migration, US-03/EUDISTACK-535)
 *       already enforces this for application writes; this indicator is defense-in-depth
 *       against out-of-band data manipulation. DOWN if any orphaned handle is found.
 * </ol>
 */
@Component
@RequiredArgsConstructor
public class HybridHealthContributor implements ReactiveHealthIndicator {

    private final WalletProfileQueryPort walletProfileQueryPort;
    private final WrappedKeyHandleRepository wrappedKeyHandleRepository;
    private final MeterRegistry meterRegistry;
    private final HybridKeyManagerTelemetry telemetry;

    @Override
    public Mono<Health> health() {
        return walletProfileQueryPort.queryByCurrentTenant()
                .map(profile -> profile.keyManager() == KeyManager.HYBRID)
                .onErrorReturn(false)
                .flatMap(isHybrid -> isHybrid ? hybridHealth() : notApplicableHealth());
    }

    private Mono<Health> notApplicableHealth() {
        return Mono.just(Health.up()
                .withDetail("hybrid_applicable", false)
                .withDetail("note", "current tenant is not in hybrid key-manager mode")
                .build());
    }

    private Mono<Health> hybridHealth() {
        Mono<Health> prfMono  = Mono.fromSupplier(this::prfGateRateHealth);
        Mono<Health> saltMono = saltCoherentHealth();
        Mono<Health> wrapMono = wrappedKeyHandleRepository.count()
                .doOnNext(telemetry::updateWrapHandlesTotal)
                .map(count -> Health.up().withDetail("wrap_handles_total", count).build())
                .onErrorResume(e -> Mono.just(
                        Health.down().withDetail("wrap_handles_error", e.getMessage()).build()));

        return Mono.zip(prfMono, saltMono, wrapMono)
                .map(tuple -> combineHealth(tuple.getT1(), tuple.getT2(), tuple.getT3()))
                .onErrorResume(e -> Mono.just(Health.down().withException(e).build()));
    }

    private Health prfGateRateHealth() {
        double attempts = sumCounter(HybridKeyManagerTelemetry.METRIC_PRF_ATTEMPTS);
        double passes   = sumCounter(HybridKeyManagerTelemetry.METRIC_PRF_PASSES);

        if (attempts == 0.0) {
            return Health.up()
                    .withDetail("prf_gate_pass_rate", 1.0)
                    .withDetail("prf_gate_pass_rate_note", "no attempts yet")
                    .build();
        }

        double rate = passes / attempts;
        if (rate >= 0.75) {
            return Health.up().withDetail("prf_gate_pass_rate", rate).build();
        }
        return Health.down().withDetail("prf_gate_pass_rate", rate).build();
    }

    private Mono<Health> saltCoherentHealth() {
        return wrappedKeyHandleRepository.countOrphaned()
                .map(orphaned -> orphaned == 0L
                        ? Health.up().withDetail("salt_coherent", true).build()
                        : Health.down()
                                .withDetail("salt_coherent", false)
                                .withDetail("salt_coherent_orphaned_count", orphaned)
                                .build())
                .onErrorResume(e -> Mono.just(Health.down()
                        .withDetail("salt_coherent_error", e.getMessage())
                        .build()));
    }

    private Health combineHealth(Health prf, Health salt, Health wrap) {
        boolean down = Status.DOWN.equals(prf.getStatus())
                || Status.DOWN.equals(wrap.getStatus())
                || Status.DOWN.equals(salt.getStatus());
        Health.Builder builder = down ? Health.down() : Health.up();
        prf.getDetails().forEach(builder::withDetail);
        wrap.getDetails().forEach(builder::withDetail);
        salt.getDetails().forEach(builder::withDetail);
        return builder.build();
    }

    private double sumCounter(String name) {
        return meterRegistry.find(name).counters().stream()
                .mapToDouble(Counter::count)
                .sum();
    }
}
