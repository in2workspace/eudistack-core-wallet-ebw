package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.SecurityProperties;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.application.EnrollHolderUseCase;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitResponse;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
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
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Web-layer integration tests for {@link HybridOnboardingController}.
 *
 * <p>Covers:
 * <ul>
 *   <li>US-08 AC-01 — PRF-unsupported → audit emitted → 204</li>
 *   <li>US-08 — DB tenant on prf-unsupported → 403 opaque</li>
 *   <li>US-08 — audit failure on prf-unsupported → 500</li>
 *   <li>US-02 AC-07 — commit with HYBRID tenant → 201 (verifies tenantId extraction wire-up)</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-534 (US-02), EUDISTACK-540 (US-08).</p>
 */
@WebFluxTest(controllers = HybridOnboardingController.class)
@Import(HybridKeyManagerExceptionHandler.class)
@WithMockUser
class HybridOnboardingControllerIT {

    private static final String COMMIT_URL          = "/api/v1/keys/hybrid/onboarding/commit";
    private static final String PRF_UNSUPPORTED_URL = "/api/v1/keys/hybrid/onboarding/prf-unsupported";

    // Minimal valid commit payload fixtures
    private static final byte[] BLOB_BYTES = new byte[48];
    private static final byte[] IV_BYTES   = new byte[12];
    private static final byte[] TAG_BYTES  = new byte[16];

    private static final String BLOB_B64 = Base64.getUrlEncoder().withoutPadding().encodeToString(BLOB_BYTES);
    private static final String IV_B64   = Base64.getUrlEncoder().withoutPadding().encodeToString(IV_BYTES);
    private static final String TAG_B64  = Base64.getUrlEncoder().withoutPadding().encodeToString(TAG_BYTES);

    @MockitoBean EnrollHolderUseCase enrollHolderUseCase;
    @MockitoBean WalletProfileQueryPort walletProfileQueryPort;
    @MockitoBean KeyAuditPort keyAuditPort;
    @MockitoBean TokenSigner tokenSigner;
    @MockitoBean WalletProfileQueryTelemetry walletProfileQueryTelemetry;

    @Autowired WebTestClient webTestClient;

    // --- US-08: prf-unsupported happy path ---

    @Test
    void prfUnsupported_givenHybridTenant_emitsAuditAndReturns204() {
        UUID actorId = UUID.randomUUID();
        stubHybridProfile();
        when(keyAuditPort.emit(any(KeyAuditEvent.class))).thenReturn(Mono.empty());

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", List.of())))
                .post().uri(PRF_UNSUPPORTED_URL)
                .exchange()
                .expectStatus().isNoContent()
                .expectBody().isEmpty();

        verify(keyAuditPort).emit(argThat(event ->
                event.type() == KeyAuditEventType.ONBOARDING_BLOCKED_PRF_UNSUPPORTED
                && event.holderId().equals(actorId.toString())
                && event.credentialId() == null));
    }

    @Test
    void prfUnsupported_givenDbTenant_returns403Opaque() {
        UUID actorId = UUID.randomUUID();
        stubDbProfile();

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", List.of())))
                .post().uri(PRF_UNSUPPORTED_URL)
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().isEmpty();
    }

    @Test
    void prfUnsupported_givenAuditFailure_returns500() {
        UUID actorId = UUID.randomUUID();
        stubHybridProfile();
        when(keyAuditPort.emit(any(KeyAuditEvent.class)))
                .thenReturn(Mono.error(new RuntimeException("cloudwatch unavailable")));

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", List.of())))
                .post().uri(PRF_UNSUPPORTED_URL)
                .exchange()
                .expectStatus().is5xxServerError();
    }

    // --- US-02 commit: verify tenantId extraction wire-up ---

    @Test
    void commit_givenHybridTenantAndValidRequest_returns201() {
        UUID actorId = UUID.randomUUID();
        stubHybridProfile();
        when(enrollHolderUseCase.commit(any(), any(), any()))
                .thenReturn(Mono.just(new EnrollHolderCommitResponse("cred-1", false)));

        webTestClient
                .mutateWith(SecurityMockServerConfigurers.mockAuthentication(
                        new JwtAuthenticationToken(actorId, "user@test.com", List.of())))
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
            return new RateLimitProperties(100, 100, 100, 100, 100, 100, Duration.ofMinutes(1));
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
