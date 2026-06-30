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
 *   <li>{@code salt_coherent} — FK integrity between {@code hybrid_wrapped_key_handle} and
 *       {@code hybrid_prf_salt}. BLOCKED until the full coherence query is validated
 *       post-migration; included as an informational detail when blocked.
 * </ol>
 *
 * <p>Global status is the worst of the thresholded indicators: DOWN if
 * {@code prf_gate_pass_rate < 0.75} or if {@code WrappedKeyHandleRepository.count()} fails.
 * {@code salt_coherent} is informational while BLOCKED.
 *
 * <p>The endpoint inherits the VPC-level isolation defined by ADR-007. Spring Security permits
 * all requests to {@code /health/**} as defence-in-depth.
 *
 * <p>Spec: EUDISTACK-541; architecture.md §5.4, §8.2.
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
        Mono<Health> saltMono = Mono.fromSupplier(this::saltCoherentHealth);
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

    private Health saltCoherentHealth() {
        // TODO(EUDISTACK-537): Replace with a real FK coherence check between
        // hybrid_wrapped_key_handle and hybrid_prf_salt. The query should be:
        //
        //   SELECT COUNT(*) FROM hybrid_wrapped_key_handle h
        //     LEFT JOIN hybrid_prf_salt s
        //       ON h.holder_id = s.holder_id AND h.credential_id = s.credential_id
        //     WHERE s.holder_id IS NULL
        //
        // Return Status.UP if the result is 0, Status.DOWN otherwise.
        return Health.up()
                .withDetail("salt_coherent", "BLOCKED")
                .withDetail("salt_coherent_reason", "Blocked on EUDISTACK-537 US-05")
                .build();
    }

    private Health combineHealth(Health prf, Health salt, Health wrap) {
        boolean down = Status.DOWN.equals(prf.getStatus()) || Status.DOWN.equals(wrap.getStatus());
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
