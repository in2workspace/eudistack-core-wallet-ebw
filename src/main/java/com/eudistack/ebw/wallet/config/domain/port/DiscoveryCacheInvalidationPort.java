package com.eudistack.ebw.wallet.config.domain.port;

import reactor.core.publisher.Mono;

/**
 * Output port — invalidates the CloudFront cache for the wallet-tenant-config discovery path.
 *
 * <p>Called by {@code TenantWalletConfigurationWriter} after a successful configuration save.
 * The implementation issues a {@code cloudfront:CreateInvalidation} for the path
 * {@code /.well-known/wallet-tenant-config} restricted to the given tenant host.
 *
 * <p>Retry policy: the adapter retries up to 3 times with exponential backoff (1 s, 2 s, 4 s)
 * before considering the invalidation exhausted. On exhaustion, the adapter records a
 * {@code CACHE_INVALIDATION_FAILED} audit entry via {@link ConfigurationAuditPort} and
 * completes without re-throwing, so that the write-path response is not degraded (AD-S3).
 *
 * <p>The method is idempotent: calling {@code invalidate} for the same host multiple times
 * produces independent CloudFront invalidation requests, each with a unique
 * {@code CallerReference}. CloudFront deduplicates by path, not by reference.
 *
 * <p>Zero framework imports — domain layer interface only.
 * The implementing adapter lives in {@code infrastructure/cloudfront}.
 */
public interface DiscoveryCacheInvalidationPort {

    /**
     * Requests invalidation of the cached discovery response for the given tenant host.
     *
     * <p>This method MUST NOT throw even when all retry attempts are exhausted.
     * Failure is reported through the audit port (fire-and-forget with bounded retry, AD-S3).
     *
     * @param tenantHost the tenant hostname for which to invalidate the cache
     *                   (e.g. {@code acme.eudiw.example.com})
     * @return a {@link Mono} that completes when the invalidation has been submitted
     *         (or when failure has been audited after retry exhaustion)
     */
    Mono<Void> invalidate(String tenantHost);
}
