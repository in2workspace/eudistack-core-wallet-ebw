package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimitWebFilter implements WebFilter, Ordered {

    private static final String HYBRID_ONBOARDING_INIT = "/api/v1/keys/hybrid/onboarding/init";
    private static final String HYBRID_ONBOARDING_COMMIT = "/api/v1/keys/hybrid/onboarding/commit";
    private static final String HYBRID_SIGN_PREPARE = "/api/v1/keys/hybrid/sign/prepare";
    private static final String HYBRID_SIGN_SUBMIT = "/api/v1/keys/hybrid/sign/submit";

    private final RateLimitProperties properties;
    private final ObjectMapper objectMapper;
    private final Cache<String, AtomicInteger> cache;

    public RateLimitWebFilter(RateLimitProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(properties.window())
                .maximumSize(100_000)
                .build();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var request = exchange.getRequest();
        if (!HttpMethod.POST.equals(request.getMethod())) {
            return chain.filter(exchange);
        }

        var path = request.getPath().value();
        var ip = resolveIp(exchange);

        Mono<Void> result = switch (path) {
            case "/api/v1/auth/register" -> checkRateLimit("register:ip:" + ip, properties.registerPerIp())
                    .then(chain.filter(exchange));
            case "/api/v1/auth/verify-email" -> checkRateLimit("verify:ip:" + ip, properties.verifyPerIp())
                    .then(chain.filter(exchange));
            case "/api/v1/auth/refresh" -> checkRateLimit("refresh:ip:" + ip, properties.refreshPerIp())
                    .then(chain.filter(exchange));
            case "/api/v1/auth/logout" -> checkRateLimit("logout:ip:" + ip, properties.logoutPerIp())
                    .then(chain.filter(exchange));
            case HYBRID_ONBOARDING_INIT, HYBRID_ONBOARDING_COMMIT, HYBRID_SIGN_PREPARE, HYBRID_SIGN_SUBMIT ->
                    checkRateLimit("hybrid:ip:" + ip, properties.hybridSignPerIp())
                            .then(chain.filter(exchange));
            default -> chain.filter(exchange);
        };

        // A WebFilter runs outside the DispatcherHandler's exception-handling scope,
        // so @ControllerAdvice (GlobalExceptionHandler) never sees this error — it
        // must be turned into a response here, or it falls through to a generic 500.
        return result.onErrorResume(RateLimitExceededException.class, ex -> writeRateLimitResponse(exchange, ex));
    }

    private Mono<Void> checkRateLimit(String key, int limit) {
        var counter = cache.get(key, k -> new AtomicInteger(0));
        if (counter.incrementAndGet() > limit) {
            var retryAfter = properties.window().toSeconds();
            return Mono.error(new RateLimitExceededException(retryAfter));
        }
        return Mono.empty();
    }

    private Mono<Void> writeRateLimitResponse(ServerWebExchange exchange, RateLimitExceededException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:rate-limit-exceeded"));

        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        response.getHeaders().add("Retry-After", String.valueOf(ex.getRetryAfterSeconds()));

        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(problem);
        } catch (Exception e) {
            body = new byte[0];
        }
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }

    private String resolveIp(ServerWebExchange exchange) {
        var forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        var remoteAddress = exchange.getRequest().getRemoteAddress();
        return remoteAddress != null ? remoteAddress.getAddress().getHostAddress() : "unknown";
    }
}
