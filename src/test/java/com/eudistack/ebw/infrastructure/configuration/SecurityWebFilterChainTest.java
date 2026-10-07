package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationWebFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link SecurityConfig#securityWebFilterChain} rules, built with {@code ServerHttpSecurity.http()}
 * and exercised through {@link WebTestClient#bindToController} — no Spring context, no Docker. Covers public vs.
 * protected routes, the 401 entry point and the hardening headers. End-to-end checks with the real controllers live
 * in {@code CredentialFilterSecurityIntegrationTest}.
 */
class SecurityWebFilterChainTest {

    private WebTestClient client;

    @BeforeEach
    void setUp() {
        var tokenSigner = mock(TokenSigner.class);
        when(tokenSigner.verify("valid-token"))
                .thenReturn(Map.of("sub", UUID.randomUUID().toString(), "email", "holder@example.com"));
        when(tokenSigner.verify("forged-token")).thenThrow(new InvalidTokenException("Invalid JWT signature"));
        var config = new SecurityConfig(new JwtAuthenticationWebFilter(tokenSigner));
        var chain = config.securityWebFilterChain(ServerHttpSecurity.http());
        // An absolute base URL is required: the CORS processor compares the Origin with the request's scheme/host.
        client = WebTestClient.bindToController(new StubController())
                .webFilter(new WebFilterChainProxy(chain))
                .configureClient()
                .baseUrl("https://ebw.local")
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
    void publicAuthRoutes_areReachableWithoutTokenAndWithoutCsrfToken() {
        // Act + Assert
        for (var path : new String[]{"/api/v1/auth/register", "/api/v1/auth/verify-email",
                "/api/v1/auth/refresh", "/api/v1/auth/logout"}) {
            client.post().uri(path).exchange().expectStatus().isOk();
        }
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
    void corsPreflight_currentConfiguration_echoesTheOriginWithCredentials() {
        // Documents the behaviour introduced when the CORS allowlist was replaced by a wildcard origin pattern
        // (SecurityConfig#corsConfigurationSource). If an allowlist is reinstated, this test must change.
        // Act + Assert
        client.options().uri("/api/v1/credentials")
                .header(HttpHeaders.ORIGIN, "https://any-origin.example")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.GET.name())
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://any-origin.example")
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
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
                "/api/v1/auth/logout"})
        Mono<String> auth() {
            return Mono.just("auth");
        }

        @GetMapping({"/health", "/.well-known/wallet-config-metadata"})
        Mono<String> open() {
            return Mono.just("open");
        }
    }
}
