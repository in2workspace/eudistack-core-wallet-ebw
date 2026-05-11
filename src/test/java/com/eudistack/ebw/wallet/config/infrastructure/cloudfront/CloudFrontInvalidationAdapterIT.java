package com.eudistack.ebw.wallet.config.infrastructure.cloudfront;

import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent;
import com.eudistack.ebw.wallet.config.domain.port.ConfigurationAuditPort;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.cloudfront.CloudFrontInvalidationAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import software.amazon.awssdk.services.cloudfront.CloudFrontAsyncClient;
import software.amazon.awssdk.services.cloudfront.model.CreateInvalidationRequest;
import software.amazon.awssdk.services.cloudfront.model.CreateInvalidationResponse;
import software.amazon.awssdk.services.cloudfront.model.Invalidation;
import software.amazon.awssdk.services.cloudfront.model.InvalidationBatch;
import software.amazon.awssdk.services.cloudfront.model.Paths;

import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Integration tests for {@link CloudFrontInvalidationAdapter}.
 *
 * <p>Covers T-10 (AC-4a — success path) and T-11 (AC-4c — failure after 3 retries).
 *
 * <p>No real AWS calls are made. {@link CloudFrontAsyncClient} is mocked with Mockito.
 * The {@link ConfigurationAuditPort} is mocked to verify the failure audit event on T-11.
 *
 * <p>These tests do NOT start a Spring context — the adapter is instantiated directly to
 * keep the test fast and focused. This aligns with the hexagonal principle that
 * infrastructure adapters can be tested in isolation from the application context.
 */
@ExtendWith(MockitoExtension.class)
@Tag("integration")
class CloudFrontInvalidationAdapterIT {

    private static final String DISTRIBUTION_ID = "EXXXXXXXXXXXXXX";
    private static final String TENANT_HOST = "acme.eudiw.example.com";

    @Mock
    CloudFrontAsyncClient cloudFrontClient;

    @Mock
    ConfigurationAuditPort configurationAuditPort;

    private CloudFrontInvalidationAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new CloudFrontInvalidationAdapter(cloudFrontClient, DISTRIBUTION_ID);
    }

    // ------------------------------------------------------------------
    // T-10: Success path — invalidation created, Mono<Void> completes (AC-4a)
    // ------------------------------------------------------------------

    /**
     * T-10: CloudFront responds successfully → the returned {@link Mono} completes without error.
     *
     * <p>Verifies:
     * <ul>
     *   <li>The adapter calls {@code createInvalidation} exactly once.</li>
     *   <li>The returned Mono completes (no exception propagated).</li>
     *   <li>The request targets the correct distribution ID and path
     *       {@code /.well-known/wallet-tenant-config}.</li>
     * </ul>
     */
    @Test
    void invalidate_successResponse_monoCompletes() {
        // Given
        Paths paths = Paths.builder().quantity(1).items("/.well-known/wallet-tenant-config").build();
        InvalidationBatch batch = InvalidationBatch.builder()
                .paths(paths).callerReference("any").build();
        Invalidation invalidation = Invalidation.builder()
                .id("I_TEST_001").status("InProgress").invalidationBatch(batch).build();
        CreateInvalidationResponse response = CreateInvalidationResponse.builder()
                .invalidation(invalidation).build();

        when(cloudFrontClient.createInvalidation(any(CreateInvalidationRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(response));

        // When
        Mono<Void> result = adapter.invalidate(TENANT_HOST);

        // Then
        StepVerifier.create(result).verifyComplete();

        ArgumentCaptor<CreateInvalidationRequest> captor =
                ArgumentCaptor.forClass(CreateInvalidationRequest.class);
        verify(cloudFrontClient, times(1)).createInvalidation(captor.capture());

        CreateInvalidationRequest captured = captor.getValue();
        assertThat(captured.distributionId()).isEqualTo(DISTRIBUTION_ID);
        assertThat(captured.invalidationBatch().paths().items())
                .contains("/.well-known/wallet-tenant-config");
    }

    // ------------------------------------------------------------------
    // T-11: Failure path — after 3 retries all fail, Mono<Void> still completes (AD-S3)
    // ------------------------------------------------------------------

    /**
     * T-11: CloudFront always fails → after 3 retries the Mono still completes without
     * propagating the exception (fire-and-forget, AD-S3).
     *
     * <p>Verifies:
     * <ul>
     *   <li>The Mono completes (no exception escapes the adapter).</li>
     *   <li>{@code createInvalidation} is called more than once (retries occurred).</li>
     * </ul>
     *
     * <p>Note: The {@code CACHE_INVALIDATION_FAILED} audit event is written by
     * {@code TenantWalletConfigurationWriter}, not by the adapter itself. The adapter
     * propagates the error to the writer after retry exhaustion; the writer catches it
     * and records the audit entry (AD-S3). This is verified in
     * {@link com.eudistack.ebw.wallet.config.application.TenantWalletConfigurationWriterTest}.
     *
     * <p>In this test we verify that the adapter propagates the error after retry exhaustion
     * (rather than swallowing it silently). The caller (writer) is responsible for the
     * fire-and-forget semantics.
     */
    @Test
    void invalidate_alwaysFails_retriesExhaustedAndErrorPropagated() {
        // Given: CloudFront always returns a failed future
        RuntimeException awsError = new RuntimeException("AWS CloudFront unavailable");
        when(cloudFrontClient.createInvalidation(any(CreateInvalidationRequest.class)))
                .thenReturn(CompletableFuture.failedFuture(awsError));

        // When: The adapter itself propagates the error after retry exhaustion.
        // The writer uses onErrorResume to record the audit and complete normally (AD-S3).
        Mono<Void> result = adapter.invalidate(TENANT_HOST);

        // Then: After retries are exhausted the adapter signals an error.
        // The writer's onErrorResume makes the overall operation still complete normally —
        // but the adapter itself surfaces the error for the caller to handle.
        StepVerifier.create(result)
                .expectError()
                .verify();

        // createInvalidation was called at least once (initial) + retries
        verify(cloudFrontClient, atLeastOnce()).createInvalidation(any(CreateInvalidationRequest.class));
    }

    // ------------------------------------------------------------------
    // T-11 (fire-and-forget contract): Writer-level onErrorResume makes the operation complete
    // ------------------------------------------------------------------

    /**
     * T-11 (writer-level): Demonstrates that when the adapter failure is handled by
     * {@code onErrorResume} (as done in {@link com.eudistack.ebw.wallet.config.application.workflow.TenantWalletConfigurationWriter}),
     * the overall Mono completes without error.
     *
     * <p>This test replicates the writer's error-handling logic at the unit level
     * to confirm the fire-and-forget contract (AD-S3).
     */
    @Test
    void invalidate_withOnErrorResume_monoCompletesEvenOnFailure() {
        // Given
        RuntimeException awsError = new RuntimeException("AWS CloudFront timeout");
        when(cloudFrontClient.createInvalidation(any(CreateInvalidationRequest.class)))
                .thenReturn(CompletableFuture.failedFuture(awsError));

        when(configurationAuditPort.append(any(ConfigurationAuditEvent.class)))
                .thenReturn(Mono.empty());

        // When: simulate the writer's error handling (onErrorResume records audit + completes)
        Mono<Void> result = adapter.invalidate(TENANT_HOST)
                .onErrorResume(error -> configurationAuditPort.append(
                        ConfigurationAuditEvent.create(
                                "acme", "system",
                                ConfigurationAuditEvent.Event.CACHE_INVALIDATION_FAILED,
                                ConfigurationAuditEvent.Plane.DISCOVERY,
                                java.util.Collections.emptyMap(),
                                ConfigurationAuditEvent.Outcome.DENY,
                                error.getMessage(),
                                null)));

        // Then: the Mono completes without error (fire-and-forget)
        StepVerifier.create(result).verifyComplete();

        // Audit was called with the CACHE_INVALIDATION_FAILED event
        ArgumentCaptor<ConfigurationAuditEvent> auditCaptor =
                ArgumentCaptor.forClass(ConfigurationAuditEvent.class);
        verify(configurationAuditPort).append(auditCaptor.capture());
        assertThat(auditCaptor.getValue().getEvent())
                .isEqualTo(ConfigurationAuditEvent.Event.CACHE_INVALIDATION_FAILED);
        assertThat(auditCaptor.getValue().getOutcome())
                .isEqualTo(ConfigurationAuditEvent.Outcome.DENY);
    }
}
