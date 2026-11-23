package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.SessionState;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;

/**
 * The state of the session ({@code sid}) of an access token: whether it is still alive and the active Wallet
 * Instance it is bound to (EUD-15 AD-2), with a short per-instance cache to bound the database load. An ended
 * session, or a revoked instance, is seen as such at most {@link #CACHE_TTL} later on other instances; this
 * instance forgets it immediately ({@link #forget}).
 */
@Component
public class ActiveSessionChecker {

    static final Duration CACHE_TTL = Duration.ofSeconds(10);

    private final AuthTokenService authTokenService;
    private final Cache<String, SessionState> cache;

    @Autowired
    public ActiveSessionChecker(AuthTokenService authTokenService) {
        this(authTokenService, Ticker.systemTicker());
    }

    /** The clock of the cache is injectable so its expiry can be tested without waiting. */
    ActiveSessionChecker(AuthTokenService authTokenService, Ticker ticker) {
        this.authTokenService = authTokenService;
        this.cache = Caffeine.newBuilder()
                .ticker(ticker)
                .expireAfterWrite(CACHE_TTL)
                .maximumSize(100_000)
                .build();
    }

    /**
     * Requires the tenant in the Reactor context (the session lives in the tenant schema). Only the answers the
     * service gives are cached: a failure propagates and an empty answer is read as an ended session without
     * being remembered, so a transient problem never pins a session as ended.
     */
    public Mono<SessionState> state(UUID sessionId) {
        return Mono.deferContextual(ctx -> {
            var key = key(ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, ""), sessionId);
            var cached = cache.getIfPresent(key);
            if (cached != null) {
                return Mono.just(cached);
            }
            return authTokenService.sessionState(sessionId)
                    // A live session without an instance is about to be bound, maybe on another replica: it is
                    // asked again every time, so the binding is seen at once (EUD-15 design §2.2).
                    .doOnNext(state -> {
                        if (!state.active() || state.hasActiveInstance()) {
                            cache.put(key, state);
                        }
                    })
                    .defaultIfEmpty(SessionState.ENDED);
        });
    }

    /** Whether the session is still alive, whatever its instance. */
    public Mono<Boolean> isActive(UUID sessionId) {
        return state(sessionId).map(SessionState::active);
    }

    /** Drops the cached state of a session this instance has just ended, bound or revoked. */
    public Mono<Void> forget(UUID sessionId) {
        return Mono.deferContextual(ctx -> {
            cache.invalidate(key(ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, ""), sessionId));
            return Mono.empty();
        });
    }

    private static String key(String tenant, UUID sessionId) {
        return tenant + ":" + sessionId;
    }
}
