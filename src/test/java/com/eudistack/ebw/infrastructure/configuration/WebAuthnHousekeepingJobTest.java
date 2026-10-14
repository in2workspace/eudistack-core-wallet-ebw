package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.RegistrationTicketRepository;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link WebAuthnHousekeepingJob}. */
@ExtendWith(MockitoExtension.class)
class WebAuthnHousekeepingJobTest {

    @Mock private ActiveTenantDirectory tenantDirectory;
    @Mock private WebAuthnCeremonyRepository ceremonyRepository;
    @Mock private RegistrationTicketRepository ticketRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;

    private WebAuthnHousekeepingJob job;

    @BeforeEach
    void setUp() {
        job = new WebAuthnHousekeepingJob(tenantDirectory, ceremonyRepository, ticketRepository, refreshTokenRepository);
    }

    @Test
    void cleanup_everyActiveTenant_deletesInItsSchemaWithTheRetentions() {
        // Arrange
        var tenantsSeen = new CopyOnWriteArrayList<String>();
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox", "kpmg"));
        when(ceremonyRepository.deleteCreatedBefore(any())).thenReturn(Mono.deferContextual(ctx -> {
            tenantsSeen.add(ctx.get(ReactorContextKeys.TENANT_DOMAIN));
            return Mono.just(2L);
        }));
        when(ticketRepository.deleteCreatedBefore(any())).thenReturn(Mono.just(1L));
        when(refreshTokenRepository.deleteSessionsEndedBefore(any())).thenReturn(Mono.just(3L));

        // Act
        StepVerifier.create(job.cleanup()).expectNext(12L).verifyComplete();

        // Assert
        assertThat(tenantsSeen).containsExactly("sandbox", "kpmg");
        var ceremonyCutoff = ArgumentCaptor.forClass(Instant.class);
        verify(ceremonyRepository, org.mockito.Mockito.times(2)).deleteCreatedBefore(ceremonyCutoff.capture());
        assertThat(ceremonyCutoff.getValue()).isCloseTo(Instant.now().minus(Duration.ofDays(1)), within(5, ChronoUnit.SECONDS));
        var sessionCutoff = ArgumentCaptor.forClass(Instant.class);
        verify(refreshTokenRepository, org.mockito.Mockito.times(2)).deleteSessionsEndedBefore(sessionCutoff.capture());
        assertThat(sessionCutoff.getValue()).isCloseTo(Instant.now().minus(Duration.ofDays(7)), within(5, ChronoUnit.SECONDS));
    }

    @Test
    void cleanup_oneTenantFails_continuesWithTheOthers() {
        // Arrange
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("broken", "sandbox"));
        when(ceremonyRepository.deleteCreatedBefore(any())).thenReturn(Mono.deferContextual(ctx ->
                "broken".equals(ctx.get(ReactorContextKeys.TENANT_DOMAIN))
                        ? Mono.error(new IllegalStateException("schema missing"))
                        : Mono.just(1L)));
        when(ticketRepository.deleteCreatedBefore(any())).thenReturn(Mono.just(0L));
        when(refreshTokenRepository.deleteSessionsEndedBefore(any())).thenReturn(Mono.just(0L));

        // Act + Assert
        StepVerifier.create(job.cleanup()).expectNext(1L).verifyComplete();
    }

    @Test
    void cleanup_registryUnavailable_deletesNothingWithoutFailing() {
        // Arrange
        when(tenantDirectory.activeTenants()).thenReturn(Flux.error(new IllegalStateException("db down")));

        // Act + Assert
        StepVerifier.create(job.cleanup()).expectNext(0L).verifyComplete();
    }
}
