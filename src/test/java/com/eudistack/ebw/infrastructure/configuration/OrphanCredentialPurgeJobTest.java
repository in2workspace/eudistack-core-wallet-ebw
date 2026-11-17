package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.application.workflow.PurgeOrphanCredentialsWorkflow;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OrphanCredentialPurgeJob}: it runs the purge once per active tenant.
 */
@ExtendWith(MockitoExtension.class)
class OrphanCredentialPurgeJobTest {

    @Mock private ActiveTenantDirectory tenantDirectory;
    @Mock private PurgeOrphanCredentialsWorkflow purgeWorkflow;

    private OrphanCredentialPurgeJob job;

    @BeforeEach
    void setUp() {
        job = new OrphanCredentialPurgeJob(tenantDirectory, purgeWorkflow);
    }

    @Nested
    @DisplayName("purge")
    class Purge {

        @Test
        @DisplayName("runs the purge in the context of every active tenant and adds up the deleted rows")
        void purge_activeTenants_runsInEachTenantContextAndSumsTheDeleted() {
            // Arrange
            var tenants = new ArrayList<String>();
            when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox", "cgcom"));
            when(purgeWorkflow.purgeExpiredOrphans(any())).thenReturn(Mono.deferContextual(ctx -> {
                tenants.add(ctx.get(ReactorContextKeys.TENANT_DOMAIN));
                return Mono.just(2L);
            }));

            // Act
            var result = job.purge();

            // Assert
            StepVerifier.create(result).expectNext(4L).verifyComplete();
            assertThat(tenants).isEqualTo(List.of("sandbox", "cgcom"));
        }

        @Test
        @DisplayName("a tenant that fails does not stop the others")
        void purge_oneTenantFails_continuesWithTheRest() {
            // Arrange
            when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox", "cgcom"));
            when(purgeWorkflow.purgeExpiredOrphans(any())).thenReturn(Mono.deferContextual(ctx ->
                    "sandbox".equals(ctx.get(ReactorContextKeys.TENANT_DOMAIN))
                            ? Mono.<Long>error(new IllegalStateException("db down"))
                            : Mono.just(3L)));

            // Act
            var result = job.purge();

            // Assert
            StepVerifier.create(result).expectNext(3L).verifyComplete();
        }

        @Test
        @DisplayName("an error listing the tenants emits zero instead of failing")
        void purge_tenantListingFails_emitsZero() {
            // Arrange
            when(tenantDirectory.activeTenants()).thenReturn(Flux.error(new IllegalStateException("db down")));

            // Act
            var result = job.purge();

            // Assert
            StepVerifier.create(result).expectNext(0L).verifyComplete();
        }
    }
}
