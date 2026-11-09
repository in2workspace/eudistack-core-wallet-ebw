package com.eudistack.ebw.infrastructure.adapter.verifier;

import com.eudistack.ebw.infrastructure.adapter.properties.VerifierProperties;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Public keys of the Verifier that signs the system tokens (design §2.6), modelled on the
 * Issuer's {@code VerifierServiceImpl}: reads {@code jwks_uri} from the Verifier's OpenID
 * discovery on its internal URL and the JWK Set from the same internal origin (the public
 * {@code jwks_uri} path is kept, only the origin is swapped).
 *
 * <p>The JWK Set is cached {@link #CACHE_TTL}. {@link #reload()} forces one read when a token
 * carries an unknown {@code kid} (key rotation, ES-04). If a read fails, the last JWK Set read is
 * used; with none, the read fails with {@link VerifierUnavailableException} (503, ES-03).
 *
 * <p>The Verifier is read at most once every {@link #MIN_RELOAD_INTERVAL}, counted from the last
 * attempt, successful or not, and concurrent reads share one request. The tokens reach this client
 * before they are authenticated, so neither unknown {@code kid}s nor a Verifier that is down or slow
 * let unauthenticated requests multiply the reads.
 */
@Slf4j
@Component
public class VerifierJwksClient {

    static final Duration CACHE_TTL = Duration.ofMinutes(10);
    static final Duration MIN_RELOAD_INTERVAL = Duration.ofSeconds(10);
    static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final ParameterizedTypeReference<Map<String, Object>> JSON_OBJECT = new ParameterizedTypeReference<>() {};

    private record Cached(JWKSet keys, Instant readAt) {}

    private final WebClient webClient;
    private final VerifierProperties properties;
    private final Clock clock;
    private final AtomicReference<Cached> cache = new AtomicReference<>();
    private final AtomicReference<Instant> lastAttempt = new AtomicReference<>();
    private final AtomicReference<Mono<JWKSet>> inFlight = new AtomicReference<>();

    @Autowired
    public VerifierJwksClient(WebClient.Builder webClientBuilder, VerifierProperties properties) {
        this(webClientBuilder.build(), properties, Clock.systemUTC());
    }

    VerifierJwksClient(WebClient webClient, VerifierProperties properties, Clock clock) {
        this.webClient = webClient;
        this.properties = properties;
        this.clock = clock;
    }

    /** The cached JWK Set, read again when older than {@link #CACHE_TTL}. */
    public Mono<JWKSet> keys() {
        var cached = cache.get();
        if (cached != null && cached.readAt().plus(CACHE_TTL).isAfter(clock.instant())) {
            return Mono.just(cached.keys());
        }
        return read();
    }

    /** Reads the JWK Set again, unless the Verifier was tried less than {@link #MIN_RELOAD_INTERVAL} ago. */
    public Mono<JWKSet> reload() {
        return read();
    }

    /**
     * One read of the Verifier shared by the concurrent callers, unless one was tried less than
     * {@link #MIN_RELOAD_INTERVAL} ago: then the last JWK Set read, or unavailable without one.
     */
    private Mono<JWKSet> read() {
        if (!properties.configured()) {
            return Mono.error(new VerifierUnavailableException("ebw.verifier.internal-url is not configured"));
        }
        var running = inFlight.get();
        if (running != null) {
            return running;
        }
        var attemptedAt = lastAttempt.get();
        if (attemptedAt != null && attemptedAt.plus(MIN_RELOAD_INTERVAL).isAfter(clock.instant())) {
            return lastRead();
        }
        var shared = fetch().doFinally(signal -> inFlight.set(null)).cache();
        if (!inFlight.compareAndSet(null, shared)) {
            var other = inFlight.get();
            return other != null ? other : lastRead();
        }
        lastAttempt.set(clock.instant());
        return shared;
    }

    private Mono<JWKSet> lastRead() {
        var cached = cache.get();
        return cached != null ? Mono.just(cached.keys())
                : Mono.error(new VerifierUnavailableException("The Verifier JWK Set could not be read recently"));
    }

    private Mono<JWKSet> fetch() {
        return Mono.defer(() -> {
                    var discoveryUrl = UriComponentsBuilder.fromUriString(properties.internalUrl())
                            .pathSegment(".well-known", "openid-configuration")
                            .build().toUriString();
                    return get(discoveryUrl, JSON_OBJECT);
                })
                .map(discovery -> {
                    if (!(discovery.get("jwks_uri") instanceof String jwksUri) || jwksUri.isBlank()) {
                        throw new VerifierUnavailableException("The Verifier discovery has no jwks_uri");
                    }
                    return toInternal(jwksUri);
                })
                .flatMap(jwksUrl -> get(jwksUrl, String.class))
                .map(VerifierJwksClient::parse)
                .doOnNext(keys -> cache.set(new Cached(keys, clock.instant())))
                .onErrorResume(e -> {
                    var stale = cache.get();
                    if (stale != null) {
                        log.warn("Could not read the Verifier JWK Set, using the last one read: {}",
                                e.getClass().getSimpleName());
                        return Mono.just(stale.keys());
                    }
                    log.error("Could not read the Verifier JWK Set: {}", e.getClass().getSimpleName());
                    return Mono.error(e instanceof VerifierUnavailableException ? e
                            : new VerifierUnavailableException("Could not read the Verifier JWK Set", e));
                });
    }

    private <T> Mono<T> get(String url, Class<T> type) {
        return webClient.get().uri(URI.create(url)).retrieve().bodyToMono(type).timeout(REQUEST_TIMEOUT);
    }

    private <T> Mono<T> get(String url, ParameterizedTypeReference<T> type) {
        return webClient.get().uri(URI.create(url)).retrieve().bodyToMono(type).timeout(REQUEST_TIMEOUT);
    }

    /** Keeps the path of the public {@code jwks_uri} and swaps its origin for the internal one. */
    String toInternal(String publicJwksUri) {
        var publicUri = URI.create(publicJwksUri);
        var internal = URI.create(properties.internalUrl());
        return UriComponentsBuilder.newInstance()
                .scheme(internal.getScheme())
                .host(internal.getHost())
                .port(internal.getPort())
                .path(publicUri.getRawPath())
                .query(publicUri.getRawQuery())
                .build(true)
                .toUriString();
    }

    private static JWKSet parse(String body) {
        try {
            return JWKSet.parse(body);
        } catch (ParseException e) {
            throw new VerifierUnavailableException("The Verifier JWK Set is not valid", e);
        }
    }
}
