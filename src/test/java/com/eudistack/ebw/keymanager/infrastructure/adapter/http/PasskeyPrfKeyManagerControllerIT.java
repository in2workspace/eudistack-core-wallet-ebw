package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.spi.IpRateLimiter;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.keymanager.application.EnrollHolderUseCase;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.SecurityProperties;
import com.eudistack.ebw.support.InMemoryIpRateLimiter;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import com.eudistack.ebw.infrastructure.security.ClientIpResolver;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.domain.exception.SignatureInvalidException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
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
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Web-layer integration tests for {@link PasskeyPrfKeyManagerController}.
 *
 * <p>Uses {@code @WebFluxTest} slice — no DB, no Testcontainers. The adapter and
 * wallet-profile port are replaced with Mockito beans.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-05 / ES-01 — unsupported format → 400 {@code error=unsupported_format}</li>
 *   <li>AC-03 — PASSKEY_PRF tenant + supported format → adapter called (stub → 500 in US-01)</li>
 *   <li>ES-02 — DB tenant on passkey-prf endpoint → 403 opaque</li>
 *   <li>ES-03 — submit with invalid signature → 400 {@code error=signature_invalid}</li>
 *   <li>ES-01 — missing required field → 400</li>
 *   <li>US-06 AC-02 — PASSKEY_PRF tenant accepts constraint → audit recorded → 204</li>
 *   <li>US-06 — DB tenant on constraint-accepted → 403 opaque</li>
 *   <li>US-06 — audit failure propagates as 500</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-533 AC-03, AC-04, AC-05, ES-01, ES-02, ES-03;
 * EUDISTACK-538 (US-06) AC-02.</p>
 */
@WebFluxTest(controllers = PasskeyPrfKeyManagerController.class)
@Import({PasskeyPrfKeyManagerExceptionHandler.class,
        com.eudistack.ebw.infrastructure.controller.support.RefreshCookies.class})
@WithMockUser
class PasskeyPrfKeyManagerControllerIT {

    @org.junit.jupiter.api.BeforeEach
    void stubActiveSessions() {
        org.mockito.Mockito.lenient().when(activeSessionChecker.isActive(org.mockito.ArgumentMatchers.any()))
                .thenReturn(reactor.core.publisher.Mono.just(true));
    }

    private static final String PREPARE_URL             = "/api/v1/keys/passkey-prf/sign/prepare";
    private static final String SUBMIT_URL              = "/api/v1/keys/passkey-prf/sign/submit";
    private static final String CONSTRAINT_ACCEPTED_URL = "/api/v1/keys/passkey-prf/constraint-accepted";

    /** Sessions of the mocked tokens only exist in the mock: the session check is covered by PasskeySessionIT. */
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    com.eudistack.ebw.infrastructure.security.ActiveSessionChecker activeSessionChecker;

    /** Named as the real bean: the controller asks for it with @Qualifier. */
    @MockitoBean(name = "passkeyPrfKeyManagerAdapter")
    KeyManagerPort passkeyPrfAdapter;

    @MockitoBean
    WalletProfileQueryPort walletProfileQueryPort;

    @MockitoBean
    EnrollHolderUseCase enrollHolderUseCase;

    @MockitoBean
    TokenSigner tokenSigner;

    @MockitoBean
    WalletProfileQueryTelemetry walletProfileQueryTelemetry;

    @Autowired
    WebTestClient webTestClient;

    // --- AC-05 / ES-01: unsupported format → 400 unsupported_format ---

    @Test
    void prepare_givenPasskeyPrfTenantAndUnsupportedFormat_returns400WithUnsupportedFormat() {
        // Arrange
        stubPasskeyPrfProfile();
        when(passkeyPrfAdapter.prepareSign(any()))
                .thenReturn(Mono.error(new UnsupportedCredentialFormatException("mso_mdoc")));

        // Act & Assert
        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(UUID.randomUUID(), "user@test.com", UUID.randomUUID(), UUID.randomUUID(), List.of())))
                .post().uri(PREPARE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                        {"credential_id":"cred-1","payload":{"nonce":"ch"},"format":"mso_mdoc"}
                        """)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("unsupported_format");
    }

    // --- AC-03: PASSKEY_PRF tenant + supported format → adapter delegated (US-01 stub → 500) ---

    @Test
    void prepare_givenPasskeyPrfTenantAndSupportedFormat_delegatesToAdapter() {
        // Arrange
        stubPasskeyPrfProfile();
        when(passkeyPrfAdapter.prepareSign(any()))
                .thenReturn(Mono.error(new UnsupportedOperationException("skeleton")));

        // Act & Assert — the adapter is mocked to fail, so the catch-all answers 500.
        // This only confirms the request passed the format guard and reached the adapter.
        webTestClient.post().uri(PREPARE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                        {"credential_id":"cred-1","payload":{"nonce":"ch"},"format":"vc+sd-jwt"}
                        """)
                .exchange()
                .expectStatus().is5xxServerError();
    }

    // --- ES-02: DB tenant on passkey-prf endpoint → 403 opaque ---

    @Test
    void prepare_givenDbTenant_returns403Opaque() {
        // Arrange
        stubDbProfile();

        // Act & Assert
        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(UUID.randomUUID(), "user@test.com", UUID.randomUUID(), UUID.randomUUID(), List.of())))
                .post().uri(PREPARE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                        {"credential_id":"cred-1","payload":{"nonce":"ch"},"format":"vc+sd-jwt"}
                        """)
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    // --- ES-03: submit with invalid signature → 400 signature_invalid ---

    @Test
    void submit_givenSignatureInvalidException_returns400WithSignatureInvalid() {
        // Arrange
        stubPasskeyPrfProfile();
        when(passkeyPrfAdapter.submitSignedAssertion(any()))
                .thenReturn(Mono.error(new SignatureInvalidException()));

        // Act & Assert
        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(UUID.randomUUID(), "user@test.com", UUID.randomUUID(), UUID.randomUUID(), List.of())))
                .post().uri(SUBMIT_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                        {"credential_id":"cred-1","signature":"sig-abc","correlation_id":"corr-1"}
                        """)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("signature_invalid");
    }

    // --- ES-01: missing required field → 400 ---

    @Test
    void prepare_givenMissingCredentialId_returns400() {
        // Arrange
        stubPasskeyPrfProfile();

        // Act & Assert
        webTestClient.post().uri(PREPARE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                        {"payload":{"nonce":"ch"},"format":"vc+sd-jwt"}
                        """)
                .exchange()
                .expectStatus().isBadRequest();
    }

    // --- US-06 AC-02: constraint-accepted ---

    @Test
    void acceptConstraint_givenPasskeyPrfTenant_recordsAuditAndReturns204() {
        // Arrange
        UUID actorId = UUID.randomUUID();
        stubPasskeyPrfProfile();
        when(enrollHolderUseCase.recordConsent(any(), any())).thenReturn(Mono.empty());

        // Act & Assert
        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", UUID.randomUUID(), UUID.randomUUID(), List.of())))
                .post().uri(CONSTRAINT_ACCEPTED_URL)
                .exchange()
                .expectStatus().isNoContent()
                .expectBody().isEmpty();

        // Assert
        verify(enrollHolderUseCase).recordConsent("test-tenant", actorId.toString());
    }

    @Test
    void acceptConstraint_givenDbTenant_returns403Opaque() {
        // Arrange
        UUID actorId = UUID.randomUUID();
        stubDbProfile();

        // Act & Assert
        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", UUID.randomUUID(), UUID.randomUUID(), List.of())))
                .post().uri(CONSTRAINT_ACCEPTED_URL)
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    @Test
    void acceptConstraint_givenAuditFailure_returns500() {
        // Arrange
        UUID actorId = UUID.randomUUID();
        stubPasskeyPrfProfile();
        when(enrollHolderUseCase.recordConsent(any(), any()))
                .thenReturn(Mono.error(new RuntimeException("audit unavailable")));

        // Act & Assert
        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", UUID.randomUUID(), UUID.randomUUID(), List.of())))
                .post().uri(CONSTRAINT_ACCEPTED_URL)
                .exchange()
                .expectStatus().is5xxServerError();
    }

    // --- helpers ---

    private void stubPasskeyPrfProfile() {
        TenantWalletProfile profile = new TenantWalletProfile(
                "passkey-prf-tenant", WalletMode.SERVER, KeyManager.PASSKEY_PRF,
                Instant.now(), Instant.now());
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile));
    }

    private void stubDbProfile() {
        TenantWalletProfile profile = new TenantWalletProfile(
                "db-tenant", WalletMode.SERVER, KeyManager.DB,
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
            return new RateLimitProperties(100, 100, 100, 100, 100, 100, 100, 100, 2, Duration.ofMinutes(1));
        }

        @Bean
        ClientIpResolver clientIpResolver(RateLimitProperties properties) {
            return new ClientIpResolver(properties);
        }

        @Bean
        IpRateLimiter ipRateLimiter(RateLimitProperties properties) {
            return new InMemoryIpRateLimiter(properties.window());
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
