package com.eudistack.ebw.wallet.config.infrastructure.adapter.cloudfront;

import com.eudistack.ebw.wallet.config.domain.port.DiscoveryCacheInvalidationPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import software.amazon.awssdk.services.cloudfront.CloudFrontAsyncClient;
import software.amazon.awssdk.services.cloudfront.model.CreateInvalidationRequest;
import software.amazon.awssdk.services.cloudfront.model.InvalidationBatch;
import software.amazon.awssdk.services.cloudfront.model.Paths;

import java.time.Duration;
import java.util.UUID;

/**
 * AWS CloudFront implementation of {@link DiscoveryCacheInvalidationPort}.
 *
 * <p>Issues a {@code cloudfront:CreateInvalidation} for the path
 * {@code /.well-known/wallet-tenant-config} on the configured distribution,
 * targeting the discovery response cached for the given tenant host.
 *
 * <p><strong>Retry policy (AD-S3):</strong> up to 3 attempts with exponential
 * backoff: 1 s, 2 s, 4 s. On retry exhaustion the exception is propagated to the
 * caller ({@code TenantWalletConfigurationWriter}), which records a
 * {@code CACHE_INVALIDATION_FAILED} audit entry and completes the write-path response
 * normally — the write-path is not rolled back (fire-and-forget, AD-S3).
 *
 * <p><strong>Idempotency:</strong> Each call generates a unique {@code CallerReference}
 * (UUID). CloudFront deduplicates by path, not by reference, so multiple calls for the
 * same path are safe.
 *
 * <p>The IAM role attached to the EBW ECS task must have
 * {@code cloudfront:CreateInvalidation} on the distribution ARN (IaC, Task 8).
 */
public class CloudFrontInvalidationAdapter implements DiscoveryCacheInvalidationPort {

    private static final Logger log = LoggerFactory.getLogger(CloudFrontInvalidationAdapter.class);

    private static final String DISCOVERY_PATH = "/.well-known/wallet-tenant-config";
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final Duration INITIAL_BACKOFF = Duration.ofSeconds(1);

    private final CloudFrontAsyncClient cloudFrontClient;
    private final String distributionId;

    public CloudFrontInvalidationAdapter(
            CloudFrontAsyncClient cloudFrontClient,
            String distributionId) {
        this.cloudFrontClient = cloudFrontClient;
        this.distributionId = distributionId;
    }

    /**
     * Requests a CloudFront cache invalidation for the wallet-tenant-config discovery path.
     *
     * <p>Retries up to 3 times with exponential backoff (1 s, 2 s, 4 s) on transient errors.
     * The Mono returned by this method propagates the error after retry exhaustion; the caller
     * is responsible for handling the failure (recording a {@code CACHE_INVALIDATION_FAILED}
     * audit entry and not re-throwing, per AD-S3).
     *
     * @param tenantHost the tenant hostname (used for logging only — CloudFront invalidates
     *                   the path globally on the distribution, but the cache varies by Host header)
     * @return a {@link Mono} that completes when the invalidation request has been submitted
     */
    @Override
    public Mono<Void> invalidate(String tenantHost) {
        String callerReference = UUID.randomUUID().toString();
        log.debug("Requesting CloudFront invalidation: distributionId={}, tenantHost={}, ref={}",
                distributionId, tenantHost, callerReference);

        CreateInvalidationRequest request = buildRequest(callerReference);

        return Mono.fromFuture(() -> cloudFrontClient.createInvalidation(request))
                .retryWhen(Retry.backoff(MAX_RETRY_ATTEMPTS, INITIAL_BACKOFF)
                        .maxBackoff(Duration.ofSeconds(8))
                        .doBeforeRetry(signal -> log.warn(
                                "Retrying CloudFront invalidation: distributionId={}, "
                                        + "tenantHost={}, attempt={}, error={}",
                                distributionId, tenantHost,
                                signal.totalRetries() + 1,
                                signal.failure().getMessage())))
                .doOnSuccess(response -> log.info(
                        "CloudFront invalidation submitted: distributionId={}, tenantHost={}, "
                                + "invalidationId={}, status={}",
                        distributionId, tenantHost,
                        response.invalidation().id(),
                        response.invalidation().status()))
                .doOnError(e -> log.error(
                        "CloudFront invalidation failed after {} retries: distributionId={}, "
                                + "tenantHost={}, error={}",
                        MAX_RETRY_ATTEMPTS, distributionId, tenantHost, e.getMessage()))
                .then();
    }

    private CreateInvalidationRequest buildRequest(String callerReference) {
        Paths paths = Paths.builder()
                .quantity(1)
                .items(DISCOVERY_PATH)
                .build();

        InvalidationBatch batch = InvalidationBatch.builder()
                .paths(paths)
                .callerReference(callerReference)
                .build();

        return CreateInvalidationRequest.builder()
                .distributionId(distributionId)
                .invalidationBatch(batch)
                .build();
    }
}
