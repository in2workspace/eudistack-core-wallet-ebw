package com.eudistack.ebw.wallet.config.infrastructure.web;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.adapter.properties.CorsProperties;
import com.eudistack.ebw.infrastructure.configuration.SecurityConfig;
import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationWebFilter;
import com.eudistack.ebw.infrastructure.security.PayloadSizeLimitWebFilter;
import com.eudistack.ebw.infrastructure.security.RateLimitWebFilter;
import com.eudistack.ebw.wallet.config.application.command.ApplyConfigurationCommand;
import com.eudistack.ebw.wallet.config.application.workflow.TenantWalletConfigurationWriter;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.controller.WalletTenantConfigAdminController;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * WebFlux slice test exercising the security filter chain and method-level authorization on
 * {@link WalletTenantConfigAdminController} (SEC-B2) and the {@code schemaName} path-variable
 * validation (SEC-B1).
 *
 * <p>Uses a stub {@link TokenSigner} bean that accepts two synthetic bearer tokens:
 * <ul>
 *   <li>{@code admin-token} → claims with {@code scope = "tenant.config.write"}</li>
 *   <li>{@code user-token} → claims with no scope (an ordinary self-registered EBW user)</li>
 *   <li>anything else → {@link InvalidTokenException}</li>
 * </ul>
 *
 * <p>The unrelated platform {@code WebFilter}s ({@link PayloadSizeLimitWebFilter},
 * {@link RateLimitWebFilter}, {@link TenantDomainWebFilter}) are excluded from the slice — they
 * pull in {@code @ConfigurationProperties} beans that this test does not need.
 *
 * <p>Tagged {@code integration} (consistent with the other admin-controller test).
 */
@WebFluxTest(controllers = WalletTenantConfigAdminController.class,
        excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE,
                classes = {PayloadSizeLimitWebFilter.class, RateLimitWebFilter.class,
                        TenantDomainWebFilter.class}))
@Import({SecurityConfig.class, JwtAuthenticationWebFilter.class,
        WalletTenantConfigAdminEndpointIT.StubBeans.class})
@Tag("integration")
class WalletTenantConfigAdminEndpointIT {

    private static final String ADMIN_TOKEN = "admin-token";
    private static final String USER_TOKEN = "user-token";

    private static final String VALID_BODY = """
            {"schema_name":"acme_bw","host":"acme-admin.eudiw.example.com","wallet_mode":"browser"}
            """;

    @Autowired
    WebTestClient webTestClient;

    @MockitoBean
    TenantWalletConfigurationWriter writer;

    @TestConfiguration
    static class StubBeans {

        @Bean
        CorsProperties corsProperties() {
            return new CorsProperties("https://example.com");
        }

        @Bean
        TokenSigner tokenSigner() {
            return new TokenSigner() {
                @Override
                public String sign(Map<String, Object> claims) {
                    throw new UnsupportedOperationException("not needed in this test");
                }

                @Override
                public Map<String, Object> verify(String token) {
                    return switch (token) {
                        case ADMIN_TOKEN -> Map.of(
                                "sub", UUID.randomUUID().toString(),
                                "email", "devops@example.com",
                                "scope", "tenant.config.write");
                        case USER_TOKEN -> Map.of(
                                "sub", UUID.randomUUID().toString(),
                                "email", "user@example.com");
                        default -> throw new InvalidTokenException("unknown test token");
                    };
                }
            };
        }
    }

    private void stubWriterReturnsBrowserDescriptor() {
        TenantWalletConfigDescriptor descriptor = TenantWalletConfigDescriptor.of(
                "acme_bw", "acme-admin.eudiw.example.com",
                WalletMode.BROWSER, Optional.empty(), false, Collections.emptyList(), 1L);
        when(writer.applyConfiguration(any(ApplyConfigurationCommand.class)))
                .thenReturn(Mono.just(descriptor));
    }

    // ------------------------------------------------------------------
    // SEC-B2: no bearer → 401
    // ------------------------------------------------------------------

    @Test
    void postWithoutBearerReturns401() {
        webTestClient.post().uri("/admin/wallet-tenant-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ------------------------------------------------------------------
    // SEC-B2: valid EBW user token but no admin scope → 403
    // ------------------------------------------------------------------

    @Test
    void postWithUserTokenWithoutScopeReturns403() {
        webTestClient.post().uri("/admin/wallet-tenant-config")
                .header("Authorization", "Bearer " + USER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isForbidden();
    }

    // ------------------------------------------------------------------
    // SEC-B2: admin-scoped token → 201 Created
    // ------------------------------------------------------------------

    @Test
    void postWithAdminScopeReturns201() {
        stubWriterReturnsBrowserDescriptor();

        webTestClient.post().uri("/admin/wallet-tenant-config")
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.schema_name").isEqualTo("acme_bw")
                .jsonPath("$.wallet_mode").isEqualTo("browser")
                .jsonPath("$.version").isEqualTo(1);
    }

    @Test
    void putWithAdminScopeReturns200() {
        stubWriterReturnsBrowserDescriptor();

        webTestClient.put().uri("/admin/wallet-tenant-config/acme_bw")
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.schema_name").isEqualTo("acme_bw");
    }

    // ------------------------------------------------------------------
    // SEC-B1: malicious schemaName path variable → 400 (never reaches the writer)
    // ------------------------------------------------------------------

    @Test
    void putWithMaliciousSchemaNameReturns400() {
        webTestClient.put().uri(uriBuilder -> uriBuilder
                        .path("/admin/wallet-tenant-config/{schemaName}")
                        .build("x_business_wallet.victim_business_wallet"))
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void putWithUppercaseSchemaNameReturns400() {
        webTestClient.put().uri("/admin/wallet-tenant-config/DROP")
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isBadRequest();
    }
}
