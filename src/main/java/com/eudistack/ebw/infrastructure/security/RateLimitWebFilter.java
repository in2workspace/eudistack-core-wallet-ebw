package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.spi.IpRateLimiter;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class RateLimitWebFilter implements WebFilter, Ordered {

    // PathPattern, like the handler mappings: a plain string comparison would miss the variants Spring still
    // routes to the controller (path parameters such as ";x=1" and percent-encoded characters).
    private static final PathPattern AUTH_ROUTES = pattern("/api/v1/auth/**");
    private static final PathPattern REGISTER = pattern("/api/v1/auth/register");
    private static final PathPattern VERIFY_EMAIL = pattern("/api/v1/auth/verify-email");
    private static final PathPattern REFRESH = pattern("/api/v1/auth/refresh");
    private static final List<PathPattern> PASSKEY_REGISTRATION = patterns(
            "/api/v1/auth/passkeys/registration/options", "/api/v1/auth/passkeys/registration");
    private static final List<PathPattern> SESSION = patterns("/api/v1/auth/sessions/options", "/api/v1/auth/sessions");
    private static final List<PathPattern> PASSKEY_PRF = patterns(
            "/api/v1/keys/passkey-prf/onboarding/init", "/api/v1/keys/passkey-prf/onboarding/commit",
            "/api/v1/keys/passkey-prf/sign/prepare", "/api/v1/keys/passkey-prf/sign/submit");

    private record Budget(String name, int limit) {
    }

    private final RateLimitProperties properties;
    private final ObjectMapper objectMapper;
    private final IpRateLimiter ipRateLimiter;
    private final ClientIpResolver clientIpResolver;

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

        // Without the base-path prefix (/business-wallet): getPath().value() includes it and would never match.
        var path = request.getPath().pathWithinApplication();

        Mono<Void> result = budgetOf(path)
                .map(budget -> ipRateLimiter
                        .check(budget.name() + ":ip:" + clientIpResolver.resolve(request), budget.limit())
                        .then(chain.filter(exchange)))
                .orElseGet(() -> chain.filter(exchange));

        // A WebFilter runs outside the DispatcherHandler's exception-handling scope,
        // so @ControllerAdvice (GlobalExceptionHandler) never sees this error — it
        // must be turned into a response here, or it falls through to a generic 500.
        return result.onErrorResume(RateLimitExceededException.class,
                ex -> writeRateLimitResponse(exchange, ex, AUTH_ROUTES.matches(path)));
    }

    private Optional<Budget> budgetOf(PathContainer path) {
        if (REGISTER.matches(path)) {
            return Optional.of(new Budget("register", properties.registerPerIp()));
        }
        if (VERIFY_EMAIL.matches(path)) {
            return Optional.of(new Budget("verify", properties.verifyPerIp()));
        }
        if (REFRESH.matches(path)) {
            return Optional.of(new Budget("refresh", properties.refreshPerIp()));
        }
        if (matchesAny(PASSKEY_REGISTRATION, path)) {
            return Optional.of(new Budget("passkey-registration", properties.passkeyRegistrationPerIp()));
        }
        if (matchesAny(SESSION, path)) {
            return Optional.of(new Budget("session", properties.sessionPerIp()));
        }
        if (matchesAny(PASSKEY_PRF, path)) {
            return Optional.of(new Budget("passkey-prf", properties.passkeyPrfSignPerIp()));
        }
        return Optional.empty();
    }

    private static boolean matchesAny(List<PathPattern> patterns, PathContainer path) {
        return patterns.stream().anyMatch(pattern -> pattern.matches(path));
    }

    private static PathPattern pattern(String route) {
        return PathPatternParser.defaultInstance.parse(route);
    }

    private static List<PathPattern> patterns(String... routes) {
        return Arrays.stream(routes).map(RateLimitWebFilter::pattern).toList();
    }

    /**
     * The registration and access API answers the contract's {@code rate_limited} problem; the
     * key manager endpoints keep their URN type.
     */
    private Mono<Void> writeRateLimitResponse(ServerWebExchange exchange, RateLimitExceededException ex,
                                              boolean authEndpoint) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage());
        problem.setType(URI.create(authEndpoint ? "rate_limited" : "urn:eudistack:error:rate-limit-exceeded"));

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
}
