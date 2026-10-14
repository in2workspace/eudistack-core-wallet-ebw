package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;

/**
 * Whether the session ({@code sid}) of an access token is still alive, with a short per-instance
 * cache to bound the database load. An ended session is seen as ended at most {@link #CACHE_TTL}
 * later on other instances; this instance forgets it immediately ({@link #forget}).
 */
@Component
public class ActiveSessionChecker {

    static final Duration CACHE_TTL = Duration.ofSeconds(10);

    private final AuthTokenService authTokenService;
    private final Cache<String, Boolean> cache = Caffeine.newBuilder()
            .expireAfterWrite(CACHE_TTL)
            .maximumSize(100_000)
            .build();

    public ActiveSessionChecker(AuthTokenService authTokenService) {
        this.authTokenService = authTokenService;
    }

    /** Requires the tenant in the Reactor context (the session lives in the tenant schema). */
    public Mono<Boolean> isActive(UUID sessionId) {
        return Mono.deferContextual(ctx -> {
            var key = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "") + ":" + sessionId;
            var cached = cache.getIfPresent(key);
            if (cached != null) {
                return Mono.just(cached);
            }
            return authTokenService.isSessionActive(sessionId)
                    .defaultIfEmpty(false)
                    .doOnNext(active -> cache.put(key, active));
        });
    }

    /** Drops the cached state of a session this instance has just ended. */
    public Mono<Void> forget(UUID sessionId) {
        return Mono.deferContextual(ctx -> {
            cache.invalidate(ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "") + ":" + sessionId);
            return Mono.empty();
        });
    }
}
