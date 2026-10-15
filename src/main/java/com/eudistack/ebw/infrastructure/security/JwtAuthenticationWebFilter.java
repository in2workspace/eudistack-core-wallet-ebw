package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.eudistack.ebw.infrastructure.controller.support.AuthProblems;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Authenticates the request with the session access token in {@code Authorization: Bearer}.
 *
 * <p>The request stays unauthenticated (and protected routes answer 401) when the bearer is
 * not a valid JWT — for instance a registration ticket, which the ticket endpoints validate
 * themselves —, when the token belongs to another tenant than the request's
 * ({@link ReactorContextKeys#TENANT_DOMAIN}, set by {@code TenantDomainWebFilter}, which runs
 * before the security chain), or when it lacks the session claims {@code sid} and {@code pkid}.
 *
 * <p>On the sensitive routes ({@link #SENSITIVE_PATHS}: key manager, attestations, issuance,
 * passkeys, signing out and ending other sessions) the token is also rejected with 401
 * {@code invalid_session} once its session has been ended, revoked or has expired, instead of
 * staying valid until the access token expires ({@link ActiveSessionChecker}, cached for at most
 * 10 seconds). On the session endpoints that 401 also clears the refresh cookie, as
 * {@code SecurityConfig} does for an unauthenticated call to them.
 *
 * <p>An entry of {@link #SENSITIVE_PATHS} ending in {@code /} covers everything below it; any
 * other entry covers that exact path and the paths below it, never a longer sibling name.
 */
@Component
public class JwtAuthenticationWebFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationWebFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    static final List<String> SENSITIVE_PATHS = List.of(
            "/api/v1/keys/", "/api/v1/credentials", "/api/v1/openid-credential-offer/",
            "/api/v1/auth/passkeys", "/api/v1/auth/sessions/current", "/api/v1/auth/sessions/others");

    /** Session endpoints, whose {@code invalid_session} also clears the refresh cookie. */
    // Fixed route of the public API contract (OpenAPI), not deployment configuration.
    private static final String SESSIONS_PATH = "/api/v1/auth/sessions/"; // NOSONAR java:S1075

    private final TokenSigner tokenSigner;
    private final ActiveSessionChecker activeSessionChecker;
    private final ObjectMapper objectMapper;
    private final RefreshCookies refreshCookies;

    public JwtAuthenticationWebFilter(TokenSigner tokenSigner, ActiveSessionChecker activeSessionChecker,
                                      ObjectMapper objectMapper, RefreshCookies refreshCookies) {
        this.tokenSigner = tokenSigner;
        this.activeSessionChecker = activeSessionChecker;
        this.objectMapper = objectMapper;
        this.refreshCookies = refreshCookies;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return chain.filter(exchange);
        }

        var token = authHeader.substring(BEARER_PREFIX.length());
        return Mono.<Map<String, Object>>fromCallable(() -> tokenSigner.verify(token))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(claims -> Mono.deferContextual(ctx -> {
                    String requestTenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, null);
                    return Mono.justOrEmpty(toAuthentication(claims, requestTenant));
                }))
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .onErrorResume(InvalidTokenException.class, e -> Mono.just(Optional.empty()))
                .flatMap(authentication -> authentication
                        .map(auth -> requireActiveSession(exchange, auth)
                                .flatMap(active -> Boolean.TRUE.equals(active)
                                        ? chain.filter(exchange)
                                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                                        : invalidSession(exchange)))
                        .orElseGet(() -> chain.filter(exchange)));
    }

    private Mono<Boolean> requireActiveSession(ServerWebExchange exchange, JwtAuthenticationToken auth) {
        if (!isSensitive(pathOf(exchange))) {
            return Mono.just(true);
        }
        return activeSessionChecker.isActive(auth.getSessionId());
    }

    static boolean isSensitive(String path) {
        return SENSITIVE_PATHS.stream().anyMatch(sensitive -> sensitive.endsWith("/")
                ? path.startsWith(sensitive)
                : path.equals(sensitive) || path.startsWith(sensitive + "/"));
    }

    private static String pathOf(ServerWebExchange exchange) {
        return exchange.getRequest().getPath().pathWithinApplication().value();
    }

    private Mono<Void> invalidSession(ServerWebExchange exchange) {
        log.debug("Access token rejected: its session is no longer active");
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        if (pathOf(exchange).startsWith(SESSIONS_PATH)) {
            response.getHeaders().add(HttpHeaders.SET_COOKIE, refreshCookies.clear().toString());
        }
        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(AuthProblems.of(HttpStatus.UNAUTHORIZED, AuthProblems.INVALID_SESSION));
        } catch (Exception _) {
            body = new byte[0];
        }
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }

    private JwtAuthenticationToken toAuthentication(Map<String, Object> claims, String requestTenant) {
        var tenant = claims.get("tenant");
        if (requestTenant == null || !requestTenant.equals(tenant)) {
            log.debug("Access token rejected: tenant does not match the request");
            return null;
        }
        var userId = parseUuid(claims.get("sub"));
        var sessionId = parseUuid(claims.get("sid"));
        var passkeyId = parseUuid(claims.get("pkid"));
        if (userId == null || sessionId == null || passkeyId == null) {
            log.debug("Access token rejected: missing session claims");
            return null;
        }
        return new JwtAuthenticationToken(userId, (String) claims.get("email"), sessionId, passkeyId,
                extractAuthorities(claims));
    }

    private static UUID parseUuid(Object value) {
        if (!(value instanceof String text)) {
            return null;
        }
        try {
            return UUID.fromString(text);
        } catch (IllegalArgumentException _) {
            return null;
        }
    }

    /**
     * Extracts PBAC powers from the JWT {@code powers} claim (string array) and maps them
     * to {@link GrantedAuthority} instances. Returns an empty list if the claim is absent.
     */
    private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        var powers = claims.get("powers");
        if (powers instanceof List<?> list) {
            return list.stream()
                    .filter(String.class::isInstance)
                    .map(p -> (GrantedAuthority) new SimpleGrantedAuthority((String) p))
                    .collect(Collectors.toList());
        }
        return List.of();
    }
}
