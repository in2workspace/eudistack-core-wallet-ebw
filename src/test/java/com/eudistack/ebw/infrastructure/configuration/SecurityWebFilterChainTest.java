package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.eudistack.ebw.infrastructure.security.TenantCorsConfigurationSource;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationWebFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link SecurityConfig#securityWebFilterChain} rules, built with {@code ServerHttpSecurity.http()}
 * and exercised through {@link WebTestClient#bindToController} — no Spring context, no Docker. Covers public vs.
 * protected routes, the 401 entry point and the hardening headers. End-to-end checks with the real controllers live
 * in {@code CredentialFilterSecurityIntegrationTest}.
 */
class SecurityWebFilterChainTest {

    private static final String TENANT = "sandbox";
    private static final String WALLET_ORIGIN = "https://sandbox.stg.eudistack.net";
    private static final String OTHER_TENANT = "othertenant";
    private static final String OTHER_ORIGIN = "https://othertenant.stg.eudistack.net";
    private static final String GLOBAL_ORIGIN = "https://status.eudistack.net";

    private WebTestClient client;
    private SecurityConfig config;

    private static com.eudistack.ebw.infrastructure.security.ActiveSessionChecker activeSessions() {
        var checker = mock(com.eudistack.ebw.infrastructure.security.ActiveSessionChecker.class);
        when(checker.isActive(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.just(true));
        return checker;
    }

    private static Map<String, Object> claims(String tenant) {
        return Map.of("sub", UUID.randomUUID().toString(), "email", "holder@example.com", "tenant", tenant,
                "sid", UUID.randomUUID().toString(), "pkid", UUID.randomUUID().toString());
    }

    private SecurityWebFilterChain securityChain() {
        return config.securityWebFilterChain(ServerHttpSecurity.http());
    }

    @BeforeEach
    void setUp() {
        var tokenSigner = mock(TokenSigner.class);
        when(tokenSigner.verify("valid-token")).thenReturn(claims(TENANT));
        when(tokenSigner.verify("other-tenant-token")).thenReturn(claims("othertenant"));
        when(tokenSigner.verify("forged-token")).thenThrow(new InvalidTokenException("Invalid JWT signature"));
        when(tokenSigner.verify("registration-ticket")).thenThrow(new InvalidTokenException("Malformed JWT"));
        var tenantOrigins = Map.of(TENANT, List.of(WALLET_ORIGIN), OTHER_TENANT, List.of(OTHER_ORIGIN));
        var cors = new TenantCorsConfigurationSource(new TenantDomainWebFilter(true),
                tenant -> tenantOrigins.getOrDefault(tenant, List.of()), List.of(GLOBAL_ORIGIN));
        config = new SecurityConfig(new JwtAuthenticationWebFilter(tokenSigner, activeSessions(),
                        new ObjectMapper()), cors,
                new RefreshCookies(), new ObjectMapper());
        // An absolute base URL is required: the CORS processor compares the Origin with the request's scheme/host.
        // The tenant filter runs before the security chain, as in the application (TenantDomainWebFilter.ORDER).
        client = WebTestClient.bindToController(new StubController())
                .webFilter(new TenantDomainWebFilter(true), new WebFilterChainProxy(securityChain()))
                .configureClient()
                .baseUrl("http://wallet-ebw.internal:8080")
                .defaultHeader("X-Tenant", TENANT)
                .build();
    }

    @Test
    void protectedRoute_withoutToken_returns401() {
        // Act + Assert
        client.get().uri("/api/v1/credentials").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void protectedRoute_withInvalidToken_returns401() {
        // Act + Assert
        client.get().uri("/api/v1/credentials")
                .header(HttpHeaders.AUTHORIZATION, "Bearer forged-token")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void protectedRoute_withValidToken_reachesTheController() {
        // Act + Assert
        client.get().uri("/api/v1/credentials")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("credentials");
    }

    @Test
    void protectedRoute_withTokenOfAnotherTenant_returns401() {
        // Act + Assert
        client.get().uri("/api/v1/credentials")
                .header(HttpHeaders.AUTHORIZATION, "Bearer other-tenant-token")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void publicAuthRoutes_areReachableWithoutTokenAndWithoutCsrfToken() {
        // Act + Assert
        for (var path : new String[]{"/api/v1/auth/register", "/api/v1/auth/verify-email",
                "/api/v1/auth/refresh", "/api/v1/auth/passkeys/registration/options",
                "/api/v1/auth/passkeys/registration", "/api/v1/auth/sessions/options", "/api/v1/auth/sessions"}) {
            client.post().uri(path).exchange().expectStatus().isOk();
        }
    }

    @Test
    void ticketEndpoint_withRegistrationTicketBearer_isNotRejectedByTheJwtFilter() {
        // Act + Assert
        client.post().uri("/api/v1/auth/passkeys/registration/options")
                .header(HttpHeaders.AUTHORIZATION, "Bearer registration-ticket")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void removedLogoutRoute_isProtected() {
        // Act + Assert
        client.post().uri("/api/v1/auth/logout").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void sessionEndpoint_withoutSession_returnsInvalidSessionProblemAndClearsCookie() {
        // Act + Assert
        client.delete().uri("/api/v1/auth/sessions/current").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentType("application/problem+json")
                .expectHeader().value(HttpHeaders.SET_COOKIE, cookie -> assertThat(cookie)
                        .startsWith("__Host-wallet_refresh=;").contains("Path=/;").contains("Max-Age=0"))
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");
    }

    @Test
    void healthAndWalletDiscovery_arePublic() {
        // Act + Assert
        client.get().uri("/health").exchange().expectStatus().isOk();
        client.get().uri("/.well-known/wallet-config-metadata").exchange().expectStatus().isOk();
        client.head().uri("/.well-known/wallet-config-metadata").exchange().expectStatus().isOk();
    }

    @Test
    void publicPathWithAnotherMethod_isStillProtected() {
        // Act + Assert — only POST is permitted on the auth endpoints
        client.get().uri("/api/v1/auth/register").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void responses_carryTheHardeningHeaders() {
        // Act + Assert
        client.get().uri("/health").exchange()
                .expectHeader().valueEquals("X-Frame-Options", "DENY")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Content-Security-Policy", "default-src 'none'")
                .expectHeader().valueEquals("Referrer-Policy", "strict-origin-when-cross-origin")
                .expectHeader().valueEquals("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    }

    @Test
    void corsPreflight_allowedOrigin_echoesTheOriginWithCredentials() {
        // Act + Assert
        client.options().uri("/api/v1/auth/refresh")
                .header(HttpHeaders.ORIGIN, WALLET_ORIGIN)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "x-wallet-request")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, WALLET_ORIGIN)
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
    }

    @Test
    void corsPreflight_foreignOrigin_isRejected() {
        // Act + Assert
        client.options().uri("/api/v1/auth/refresh")
                .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
    }

    @Test
    void post_withAllowedOrigin_passes() {
        // Act + Assert
        client.post().uri("/api/v1/auth/register")
                .header(HttpHeaders.ORIGIN, WALLET_ORIGIN)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void post_behindProxyWithAllowedOrigin_passes() {
        // The request reaches the service through ALB/nginx on an internal host, so the Origin differs from the
        // request host: it is handled as a CORS request and accepted because the origin is in the allowlist.
        WebTestClient.bindToController(new StubController())
                .webFilter(new TenantDomainWebFilter(true), new WebFilterChainProxy(securityChain()))
                .configureClient()
                .baseUrl("http://wallet-ebw.internal:8080")
                .build()
                .post().uri("/api/v1/auth/register")
                .header(HttpHeaders.ORIGIN, WALLET_ORIGIN)
                .header("X-Forwarded-Host", "sandbox.stg.eudistack.net")
                .header("X-Forwarded-Proto", "https")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, WALLET_ORIGIN);
    }

    @Test
    void post_originOfAnotherTenant_isRejected() {
        // Act + Assert — the sandbox Wallet App origin is not admitted on another tenant
        client.post().uri("/api/v1/auth/register")
                .header("X-Tenant", OTHER_TENANT)
                .header(HttpHeaders.ORIGIN, WALLET_ORIGIN)
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void post_originOfItsOwnTenant_passes() {
        // Act + Assert
        client.post().uri("/api/v1/auth/register")
                .header("X-Tenant", OTHER_TENANT)
                .header(HttpHeaders.ORIGIN, OTHER_ORIGIN)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, OTHER_ORIGIN);
    }

    @Test
    void post_behindProxyWithOriginOfAnotherTenant_isRejected() {
        // Act + Assert — the tenant comes from X-Forwarded-Host, as in TenantDomainWebFilter
        WebTestClient.bindToController(new StubController())
                .webFilter(new TenantDomainWebFilter(true), new WebFilterChainProxy(securityChain()))
                .configureClient()
                .baseUrl("http://wallet-ebw.internal:8080")
                .build()
                .post().uri("/api/v1/auth/register")
                .header(HttpHeaders.ORIGIN, WALLET_ORIGIN)
                .header("X-Forwarded-Host", OTHER_TENANT + ".stg.eudistack.net")
                .header("X-Forwarded-Proto", "https")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void healthPath_usesTheGlobalOriginsOnly() {
        // Act + Assert
        client.get().uri("/health").header(HttpHeaders.ORIGIN, GLOBAL_ORIGIN)
                .exchange().expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, GLOBAL_ORIGIN);
        client.get().uri("/health").header(HttpHeaders.ORIGIN, WALLET_ORIGIN)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void post_withForeignOrigin_isRejected() {
        // Act + Assert
        client.post().uri("/api/v1/auth/register")
                .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                .exchange()
                .expectStatus().isForbidden();
    }

    @RestController
    static class StubController {

        @GetMapping("/api/v1/credentials")
        Mono<String> credentials() {
            return Mono.just("credentials");
        }

        @GetMapping("/api/v1/auth/register")
        Mono<String> registerGet() {
            return Mono.just("unexpected");
        }

        @PostMapping({"/api/v1/auth/register", "/api/v1/auth/verify-email", "/api/v1/auth/refresh",
                "/api/v1/auth/logout", "/api/v1/auth/passkeys/registration/options",
                "/api/v1/auth/passkeys/registration", "/api/v1/auth/sessions/options", "/api/v1/auth/sessions"})
        Mono<String> auth() {
            return Mono.just("auth");
        }

        @DeleteMapping("/api/v1/auth/sessions/current")
        Mono<String> endSession() {
            return Mono.just("ended");
        }

        @GetMapping({"/health", "/.well-known/wallet-config-metadata"})
        Mono<String> open() {
            return Mono.just("open");
        }
    }
}
