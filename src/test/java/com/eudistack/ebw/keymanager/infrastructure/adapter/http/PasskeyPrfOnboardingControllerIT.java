package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.SecurityProperties;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.application.EnrollHolderUseCase;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitResponse;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Web-layer integration tests for {@link PasskeyPrfOnboardingController}.
 *
 * <p>Covers:
 * <ul>
 *   <li>US-02 AC-07 — commit with PASSKEY_PRF tenant → 201 (verifies tenantId extraction wire-up)</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-534 (US-02).</p>
 */
@WebFluxTest(controllers = PasskeyPrfOnboardingController.class)
@Import({PasskeyPrfKeyManagerExceptionHandler.class,
        com.eudistack.ebw.infrastructure.controller.support.RefreshCookies.class})
@WithMockUser
class PasskeyPrfOnboardingControllerIT {

    @org.junit.jupiter.api.BeforeEach
    void stubActiveSessions() {
        org.mockito.Mockito.lenient().when(activeSessionChecker.isActive(org.mockito.ArgumentMatchers.any()))
                .thenReturn(reactor.core.publisher.Mono.just(true));
    }

    private static final String COMMIT_URL = "/api/v1/keys/passkey-prf/onboarding/commit";

    // Minimal valid commit payload fixtures
    private static final byte[] BLOB_BYTES = new byte[48];
    private static final byte[] IV_BYTES   = new byte[12];
    private static final byte[] TAG_BYTES  = new byte[16];

    private static final String BLOB_B64 = Base64.getUrlEncoder().withoutPadding().encodeToString(BLOB_BYTES);
    private static final String IV_B64   = Base64.getUrlEncoder().withoutPadding().encodeToString(IV_BYTES);
    private static final String TAG_B64  = Base64.getUrlEncoder().withoutPadding().encodeToString(TAG_BYTES);

    /** Sessions of the mocked tokens only exist in the mock: the session check is covered by PasskeySessionIT. */
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.eudistack.ebw.infrastructure.security.ActiveSessionChecker activeSessionChecker;

    @MockitoBean EnrollHolderUseCase enrollHolderUseCase;
    @MockitoBean WalletProfileQueryPort walletProfileQueryPort;
    @MockitoBean TokenSigner tokenSigner;
    @MockitoBean WalletProfileQueryTelemetry walletProfileQueryTelemetry;

    @Autowired WebTestClient webTestClient;

    // --- US-02 commit: verify tenantId extraction wire-up ---

    @Test
    void commit_givenPasskeyPrfTenantAndValidRequest_returns201() {
        // Arrange
        UUID actorId = UUID.randomUUID();
        stubPasskeyPrfProfile();
        when(enrollHolderUseCase.commit(any(), any(), any()))
                .thenReturn(Mono.just(new EnrollHolderCommitResponse("cred-1", false)));

        // Act & Assert
        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", UUID.randomUUID(), UUID.randomUUID(), List.of())))
                .post().uri(COMMIT_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                        {
                          "credential_id": "cred-1",
                          "wrapped_blob": "%s",
                          "iv": "%s",
                          "tag": "%s",
                          "kdf_algo": "HKDF-SHA-256",
                          "kdf_version": 1,
                          "cnf_jwk": "{\\"kty\\":\\"EC\\",\\"crv\\":\\"P-256\\",\\"x\\":\\"abc\\",\\"y\\":\\"def\\"}"
                        }
                        """.formatted(BLOB_B64, IV_B64, TAG_B64))
                .exchange()
                .expectStatus().isCreated();
    }

    // --- helpers ---

    private void stubPasskeyPrfProfile() {
        TenantWalletProfile profile = new TenantWalletProfile(
                "passkey-prf-tenant", WalletMode.SERVER, KeyManager.PASSKEY_PRF,
                Instant.now(), Instant.now());
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile));
    }

    @TestConfiguration
    static class InfrastructureConfig {
        @Bean
        SecurityProperties securityProperties() {
            return new SecurityProperties(10_485_760L);
        }

        @Bean
        RateLimitProperties rateLimitProperties() {
            return new RateLimitProperties(100, 100, 100, 100, 100, 100, 100, 100, Duration.ofMinutes(1));
        }

        @Bean
        SecurityWebFilterChain testSecurityFilterChain(ServerHttpSecurity http) {
            return http
                    .csrf(ServerHttpSecurity.CsrfSpec::disable)
                    .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                    .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                    .exceptionHandling(ex -> ex
                            .accessDeniedHandler((exchange, e) -> {
                                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                                return exchange.getResponse().setComplete();
                            })
                    )
                    .authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                    .build();
        }

        @Bean
        WebFilter testTenantContextFilter() {
            return (exchange, chain) -> chain.filter(exchange)
                    .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "test-tenant"));
        }
    }
}
