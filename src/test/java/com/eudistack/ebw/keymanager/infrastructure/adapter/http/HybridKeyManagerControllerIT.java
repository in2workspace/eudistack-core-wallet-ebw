package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.SecurityProperties;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.domain.exception.SignatureInvalidException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
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
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Web-layer integration tests for {@link HybridKeyManagerController}.
 *
 * <p>Uses {@code @WebFluxTest} slice — no DB, no Testcontainers. The adapter and
 * wallet-profile port are replaced with Mockito beans.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-05 / ES-01 — unsupported format → 400 {@code error=unsupported_format}</li>
 *   <li>AC-03 — HYBRID tenant + supported format → adapter called (stub → 500 in US-01)</li>
 *   <li>ES-02 — DB tenant on hybrid endpoint → 403 opaque</li>
 *   <li>ES-03 — submit with invalid signature → 400 {@code error=signature_invalid}</li>
 *   <li>ES-01 — missing required field → 400</li>
 *   <li>US-06 AC-02 — HYBRID tenant accepts constraint → audit recorded → 204</li>
 *   <li>US-06 — DB tenant on constraint-accepted → 403 opaque</li>
 *   <li>US-06 — audit failure propagates as 500</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-533 AC-03, AC-04, AC-05, ES-01, ES-02, ES-03;
 * EUDISTACK-538 (US-06) AC-02.</p>
 */
@WebFluxTest(controllers = HybridKeyManagerController.class)
@Import(HybridKeyManagerExceptionHandler.class)
@WithMockUser
class HybridKeyManagerControllerIT {

    private static final String PREPARE_URL             = "/api/v1/keys/hybrid/sign/prepare";
    private static final String SUBMIT_URL              = "/api/v1/keys/hybrid/sign/submit";
    private static final String CONSTRAINT_ACCEPTED_URL = "/api/v1/keys/hybrid/constraint-accepted";

    @MockitoBean
    KeyManagerPort hybridAdapter;

    @MockitoBean
    WalletProfileQueryPort walletProfileQueryPort;

    @MockitoBean
    AuditService auditService;

    @MockitoBean
    TokenSigner tokenSigner;

    @MockitoBean
    WalletProfileQueryTelemetry walletProfileQueryTelemetry;

    @Autowired
    WebTestClient webTestClient;

    // --- AC-05 / ES-01: unsupported format → 400 unsupported_format ---

    @Test
    void prepare_givenHybridTenantAndUnsupportedFormat_returns400WithUnsupportedFormat() {
        stubHybridProfile();
        when(hybridAdapter.prepareSign(any()))
                .thenReturn(Mono.error(new UnsupportedCredentialFormatException("mso_mdoc")));

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(UUID.randomUUID(), "user@test.com", List.of())))
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

    // --- AC-03: HYBRID tenant + supported format → adapter delegated (US-01 stub → 500) ---

    @Test
    void prepare_givenHybridTenantAndSupportedFormat_delegatesToAdapter() {
        stubHybridProfile();
        when(hybridAdapter.prepareSign(any()))
                .thenReturn(Mono.error(new UnsupportedOperationException("skeleton")));

        // The stub throws UnsupportedOperationException (US-04 TODO) — caught by the catch-all → 500.
        // This confirms the request passed format guard and reached the adapter.
        webTestClient.post().uri(PREPARE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                        {"credential_id":"cred-1","payload":{"nonce":"ch"},"format":"vc+sd-jwt"}
                        """)
                .exchange()
                .expectStatus().is5xxServerError();
    }

    // --- ES-02: DB tenant on hybrid endpoint → 403 opaque ---

    @Test
    void prepare_givenDbTenant_returns403Opaque() {
        stubDbProfile();

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(UUID.randomUUID(), "user@test.com", List.of())))
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
        stubHybridProfile();
        when(hybridAdapter.submitSignedAssertion(any()))
                .thenReturn(Mono.error(new SignatureInvalidException()));

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(UUID.randomUUID(), "user@test.com", List.of())))
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
        stubHybridProfile();

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
    void acceptConstraint_givenHybridTenant_recordsAuditAndReturns204() {
        UUID actorId = UUID.randomUUID();
        stubHybridProfile();
        when(auditService.record(
                eq("hybrid_consent"), eq(actorId),
                eq("hybrid_constraint_accepted"), eq(actorId),
                any()))
                .thenReturn(Mono.empty());

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", List.of())))
                .post().uri(CONSTRAINT_ACCEPTED_URL)
                .exchange()
                .expectStatus().isNoContent()
                .expectBody().isEmpty();

        verify(auditService).record(
                eq("hybrid_consent"), eq(actorId),
                eq("hybrid_constraint_accepted"), eq(actorId),
                any());
    }

    @Test
    void acceptConstraint_givenDbTenant_returns403Opaque() {
        UUID actorId = UUID.randomUUID();
        stubDbProfile();

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", List.of())))
                .post().uri(CONSTRAINT_ACCEPTED_URL)
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    @Test
    void acceptConstraint_givenAuditFailure_returns500() {
        UUID actorId = UUID.randomUUID();
        stubHybridProfile();
        when(auditService.record(any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("audit unavailable")));

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", List.of())))
                .post().uri(CONSTRAINT_ACCEPTED_URL)
                .exchange()
                .expectStatus().is5xxServerError();
    }

    // --- helpers ---

    private void stubHybridProfile() {
        TenantWalletProfile profile = new TenantWalletProfile(
                "hybrid-tenant", WalletMode.SERVER, KeyManager.HYBRID,
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
            return new RateLimitProperties(100, 100, 100, 100, 100, 100, 100, Duration.ofMinutes(1));
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
    }
}
