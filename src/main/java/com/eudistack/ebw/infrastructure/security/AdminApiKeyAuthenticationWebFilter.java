package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.adapter.properties.AdminProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/**
 * Authenticates the {@code /admin/**} endpoints with a static {@code X-Admin-Api-Key} request
 * header (SEC-B2).
 *
 * <p>The expected key value is injected via {@code ADMIN_API_KEY} (an SSM parameter in STG, a
 * plain dev placeholder in local Docker Compose) and bound through {@link AdminProperties}.
 *
 * <p>Behaviour for {@code /admin/**} requests:
 * <ul>
 *   <li>If the configured key is <strong>blank/unset</strong> &rArr; <strong>fail closed</strong>:
 *       every {@code /admin/**} request is rejected with HTTP 401. There is no implicit
 *       "no key configured &rArr; open" mode. A WARN is logged once at startup.</li>
 *   <li>If the {@code X-Admin-Api-Key} header is missing or does not match &rArr; HTTP 401 with an
 *       RFC 9457 {@code application/problem+json} body
 *       ({@code type=urn:eudistack:error:admin-auth-required}).</li>
 *   <li>If it matches &rArr; the reactive {@code SecurityContext} is populated with an
 *       authenticated {@link Authentication} (principal {@code "admin-api-key"}) bearing the
 *       {@code SCOPE_tenant.config.write} authority, so the {@code SecurityConfig} URL rule and the
 *       {@code @PreAuthorize} on the handlers are satisfied (defence in depth), and the chain
 *       continues.</li>
 * </ul>
 *
 * <p>For {@code /admin/**} this API-key authentication is the <em>only</em> accepted credential —
 * a bearer JWT alone (without the API key) on an {@code /admin/**} path is rejected with 401, since
 * the JWT-derived authentication carries no admin authority and this filter short-circuits before
 * the authorization checks.
 *
 * <p>All other paths pass through untouched — this filter does not interfere with
 * {@link JwtAuthenticationWebFilter}.
 *
 * <p>The header value is compared with {@link MessageDigest#isEqual(byte[], byte[])} (constant
 * time) rather than {@link String#equals(Object)} to avoid a timing oracle on the key.
 *
 * <p>Wired in {@code SecurityConfig} immediately after {@link JwtAuthenticationWebFilter} (i.e.
 * just before the authorization checks): on {@code /admin/**} it establishes the security context
 * before authorization runs and overrides any JWT-derived context.
 */
@Component
public class AdminApiKeyAuthenticationWebFilter implements WebFilter {

    static final String API_KEY_HEADER = "X-Admin-Api-Key";

    /** Principal name reported for a successful admin API-key authentication. */
    private static final String ADMIN_PRINCIPAL = "admin-api-key";

    /** Authority granted on a successful admin API-key authentication. */
    private static final String TENANT_CONFIG_WRITE = "SCOPE_tenant.config.write";

    private static final URI PROBLEM_TYPE = URI.create("urn:eudistack:error:admin-auth-required");

    private static final Logger log =
            LoggerFactory.getLogger(AdminApiKeyAuthenticationWebFilter.class);

    /** Matches the same path set as {@code SecurityConfig.pathMatchers("/admin/**")}. */
    private static final ServerWebExchangeMatcher ADMIN_PATHS =
            new PathPatternParserServerWebExchangeMatcher("/admin/**");

    private final byte[] expectedKeyBytes;
    private final boolean keyConfigured;

    public AdminApiKeyAuthenticationWebFilter(AdminProperties adminProperties) {
        String apiKey = adminProperties.apiKey();
        this.keyConfigured = apiKey != null && !apiKey.isBlank();
        this.expectedKeyBytes = keyConfigured ? apiKey.getBytes(StandardCharsets.UTF_8) : new byte[0];
        if (!keyConfigured) {
            log.warn("ebw.admin.api-key (ADMIN_API_KEY) is not configured — all /admin/** "
                    + "requests will be rejected with 401 (fail-closed). Set ADMIN_API_KEY to "
                    + "enable the admin write endpoints.");
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ADMIN_PATHS.matches(exchange)
                .flatMap(match -> {
                    if (!match.isMatch()) {
                        return chain.filter(exchange);
                    }
                    if (!keyConfigured) {
                        return reject(exchange, "Admin API is not configured");
                    }
                    String presented = exchange.getRequest().getHeaders().getFirst(API_KEY_HEADER);
                    if (presented == null || !matches(presented)) {
                        return reject(exchange, "A valid " + API_KEY_HEADER + " header is required");
                    }
                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                            ADMIN_PRINCIPAL, null,
                            List.of(new SimpleGrantedAuthority(TENANT_CONFIG_WRITE)));
                    return chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
                });
    }

    private boolean matches(String presented) {
        return MessageDigest.isEqual(presented.getBytes(StandardCharsets.UTF_8), expectedKeyBytes);
    }

    private static Mono<Void> reject(ServerWebExchange exchange, String detail) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        String body = """
                {"type":"%s","title":"Admin authentication required","status":401,"detail":"%s"}"""
                .formatted(PROBLEM_TYPE, detail);
        var buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
