package com.eudistack.ebw.domain.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.TenantConfig;
import com.eudistack.ebw.domain.model.exception.TenantConfigMissingException;
import com.eudistack.ebw.domain.repository.TenantConfigRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
public class TenantConfigService {

    private static final Duration CACHE_TTL = Duration.ofMinutes(5);

    private final TenantConfigRepository tenantConfigRepository;
    private final Cache<String, String> cache = Caffeine.newBuilder()
            .expireAfterWrite(CACHE_TTL)
            .maximumSize(500)
            .build();

    public Mono<String> getString(String key) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "unknown");
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

    public Mono<String> getStringOrDefault(String key, String defaultValue) {
        return getString(key).defaultIfEmpty(defaultValue);
    }

    public Mono<String> getStringOrThrow(String key) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "unknown");
            return getString(key)
                    .switchIfEmpty(Mono.error(new TenantConfigMissingException(tenant, key)));
        });
    }
}
