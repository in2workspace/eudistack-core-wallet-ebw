package com.eudistack.ebw.keymanager.infrastructure.health;

import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import com.eudistack.ebw.keymanager.infrastructure.observability.HybridKeyManagerTelemetry;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link HybridHealthContributor} (US-09 / EUDISTACK-541).
 *
 * <p>Hybrid mode is a per-tenant attribute, so this indicator first resolves the tenant of
 * the current request via {@link WalletProfileQueryPort} and only runs the hybrid checks when
 * that tenant's key manager is {@link KeyManager#HYBRID}. {@link WrappedKeyHandleRepository}
 * and {@link HybridKeyManagerTelemetry} are mocked; a {@link SimpleMeterRegistry} is used to
 * inspect counter values in-process.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>Non-hybrid tenant → neutral UP, hybrid checks not run</li>
 *   <li>Tenant cannot be resolved → neutral UP (same as non-hybrid)</li>
 *   <li>prf_gate_pass_rate above threshold → UP</li>
 *   <li>prf_gate_pass_rate below threshold → DOWN</li>
 *   <li>No attempts yet → UP with "no attempts yet" note</li>
 *   <li>salt_coherent: no orphaned handles → UP</li>
 *   <li>salt_coherent: orphaned handles found → DOWN</li>
 *   <li>countOrphaned() failure → DOWN with error detail</li>
 *   <li>count() R2DBC failure → DOWN with exception in detail</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class HybridHealthContributorTest {

    private static final String TENANT = "cgcom";

    @Mock private WalletProfileQueryPort walletProfileQueryPort;
    @Mock private WrappedKeyHandleRepository repository;
    @Mock private HybridKeyManagerTelemetry telemetry;

    private MeterRegistry meterRegistry;
    private HybridHealthContributor contributor;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        contributor   = new HybridHealthContributor(walletProfileQueryPort, repository, meterRegistry, telemetry);
    }

    // ------------------------------------------------------------------ tenant resolution

    @Test
    void health_tenantNotHybrid_returnsNeutralUp_withoutRunningHybridChecks() {
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(dbModeProfile()));

        StepVerifier.create(contributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails().get("hybrid_applicable")).isEqualTo(false);
                    assertThat(health.getDetails()).doesNotContainKey("prf_gate_pass_rate");
                    assertThat(health.getDetails()).doesNotContainKey("wrap_handles_total");
                })
                .verifyComplete();
    }

    @Test
    void health_tenantUnresolvable_returnsNeutralUp() {
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.error(new TenantUnknownException(
                        TenantUnknownException.Reason.TENANT_ABSENT_FROM_CONTEXT)));

        StepVerifier.create(contributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails().get("hybrid_applicable")).isEqualTo(false);
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------ prf_gate_pass_rate

    @Test
    void health_withPrfRateAboveThreshold_returnsUp() {
        // Arrange — 8/10 = 0.80 ≥ 0.75
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(hybridProfile()));
        meterRegistry.counter(HybridKeyManagerTelemetry.METRIC_PRF_ATTEMPTS, "tenant", "t1").increment(10);
        meterRegistry.counter(HybridKeyManagerTelemetry.METRIC_PRF_PASSES,   "tenant", "t1").increment(8);
        when(repository.count()).thenReturn(Mono.just(5L));
        when(repository.countOrphaned()).thenReturn(Mono.just(0L));

        // Act + Assert
        StepVerifier.create(contributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails()).containsKey("prf_gate_pass_rate");
                    assertThat(health.getDetails()).containsKey("wrap_handles_total");
                    assertThat(health.getDetails().get("salt_coherent")).isEqualTo(true);
                    assertThat((Double) health.getDetails().get("prf_gate_pass_rate")).isGreaterThanOrEqualTo(0.75);
                })
                .verifyComplete();
    }

    @Test
    void health_withPrfRateBelowThreshold_returnsDown() {
        // Arrange — 6/10 = 0.60 < 0.75
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(hybridProfile()));
        meterRegistry.counter(HybridKeyManagerTelemetry.METRIC_PRF_ATTEMPTS, "tenant", "t1").increment(10);
        meterRegistry.counter(HybridKeyManagerTelemetry.METRIC_PRF_PASSES,   "tenant", "t1").increment(6);
        when(repository.count()).thenReturn(Mono.just(3L));
        when(repository.countOrphaned()).thenReturn(Mono.just(0L));

        // Act + Assert
        StepVerifier.create(contributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
                    assertThat((Double) health.getDetails().get("prf_gate_pass_rate")).isLessThan(0.75);
                })
                .verifyComplete();
    }

    @Test
    void health_withNoAttempts_returnsUpWithNote() {
        // Arrange — counters at zero (no attempts yet)
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(hybridProfile()));
        when(repository.count()).thenReturn(Mono.just(0L));
        when(repository.countOrphaned()).thenReturn(Mono.just(0L));

        // Act + Assert
        StepVerifier.create(contributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails().get("prf_gate_pass_rate")).isEqualTo(1.0);
                    assertThat(health.getDetails().get("prf_gate_pass_rate_note"))
                            .isEqualTo("no attempts yet");
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------ salt_coherent

    @Test
    void health_noOrphanedHandles_saltCoherentUp() {
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(hybridProfile()));
        when(repository.count()).thenReturn(Mono.just(5L));
        when(repository.countOrphaned()).thenReturn(Mono.just(0L));

        StepVerifier.create(contributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails().get("salt_coherent")).isEqualTo(true);
                })
                .verifyComplete();
    }

    @Test
    void health_orphanedHandlesFound_saltCoherentDown() {
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(hybridProfile()));
        when(repository.count()).thenReturn(Mono.just(5L));
        when(repository.countOrphaned()).thenReturn(Mono.just(2L));

        StepVerifier.create(contributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
                    assertThat(health.getDetails().get("salt_coherent")).isEqualTo(false);
                    assertThat(health.getDetails().get("salt_coherent_orphaned_count")).isEqualTo(2L);
                })
                .verifyComplete();
    }

    @Test
    void health_countOrphanedFails_returnsDown() {
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(hybridProfile()));
        when(repository.count()).thenReturn(Mono.just(5L));
        when(repository.countOrphaned()).thenReturn(Mono.error(new RuntimeException("R2DBC connection refused")));

        StepVerifier.create(contributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
                    assertThat(health.getDetails()).containsKey("salt_coherent_error");
                })
                .verifyComplete();
    }

    @Test
    void health_countFails_returnsDown() {
        // Arrange — R2DBC error from count()
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(hybridProfile()));
        RuntimeException dbError = new RuntimeException("R2DBC connection refused");
        when(repository.count()).thenReturn(Mono.error(dbError));
        when(repository.countOrphaned()).thenReturn(Mono.just(0L));

        // Act + Assert
        // count() failure is caught by wrapMono.onErrorResume → wrap is DOWN →
        // combineHealth marks overall DOWN; salt_coherent detail is still present.
        StepVerifier.create(contributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
                    assertThat(health.getDetails()).containsKey("wrap_handles_error");
                    assertThat(health.getDetails()).containsKey("salt_coherent");
                })
                .verifyComplete();
    }

    // --------------------------------------------------------------- helpers

    private TenantWalletProfile hybridProfile() {
        return new TenantWalletProfile(TENANT, WalletMode.SERVER, KeyManager.HYBRID, Instant.now(), Instant.now());
    }

    private TenantWalletProfile dbModeProfile() {
        return new TenantWalletProfile(TENANT, WalletMode.SERVER, KeyManager.DB, Instant.now(), Instant.now());
    }
}
