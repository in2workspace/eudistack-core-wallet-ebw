package com.eudistack.ebw.domain.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.eudistack.ebw.domain.model.TenantConfig;
import com.eudistack.ebw.domain.model.exception.TenantConfigMissingException;
import com.eudistack.ebw.domain.repository.TenantConfigRepository;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Reads per-tenant configuration from the {@code tenant_config} table in the
 * current tenant's schema (resolved via {@code search_path}).
 *
 * <p>Keys use the {@code ebw.} prefix convention: {@code ebw.allowed_email_domains},
 * {@code ebw.mail_from}, etc.
 *
 * <p>Values are cached per tenant for 5 minutes (Caffeine) to avoid hitting
 * the DB on every request.
 */
@Slf4j
public class TenantConfigService {

    private static final Duration CACHE_TTL = Duration.ofMinutes(5);

    private final TenantConfigRepository tenantConfigRepository;
    private final Cache<String, String> cache;

    public TenantConfigService(TenantConfigRepository tenantConfigRepository) {
        this.tenantConfigRepository = tenantConfigRepository;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(CACHE_TTL)
                .maximumSize(500)
                .build();
    }

    /**
     * Returns the config value for the given key, or empty if not found.
     */
    public Mono<String> getString(String key) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");
            String cacheKey = tenant + ":" + key;

            String cached = cache.getIfPresent(cacheKey);
            if (cached != null) {
                return Mono.just(cached);
            }

            return tenantConfigRepository.findByConfigKey(key)
                    .map(TenantConfig::configValue)
                    .doOnNext(value -> {
                        cache.put(cacheKey, value);
                        log.trace("Tenant config '{}'.'{}' = '{}'", tenant, key, value);
                    });
        });
    }

    /**
     * Returns the config value for the given key, or {@code defaultValue} if not found.
     */
    public Mono<String> getStringOrDefault(String key, String defaultValue) {
        return getString(key).defaultIfEmpty(defaultValue);
    }

    /**
     * Returns the config value for the given key, or fails with
     * {@link TenantConfigMissingException} if not present.
     * Use this for keys that MUST be seeded per tenant (no safe fallback).
     */
    public Mono<String> getStringOrThrow(String key) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");
            return getString(key)
                    .switchIfEmpty(Mono.error(new TenantConfigMissingException(tenant, key)));
        });
    }
}
