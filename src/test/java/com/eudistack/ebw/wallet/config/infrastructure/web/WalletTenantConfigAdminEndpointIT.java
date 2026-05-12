package com.eudistack.ebw.wallet.config.infrastructure.web;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.adapter.properties.AdminProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.CorsProperties;
import com.eudistack.ebw.infrastructure.configuration.SecurityConfig;
import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import com.eudistack.ebw.infrastructure.security.AdminApiKeyAuthenticationWebFilter;
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
 * WebFlux slice test exercising the security filter chain on {@link WalletTenantConfigAdminController}.
 *
 * <p>Covers SEC-B2 — the {@code /admin/**} endpoints are authenticated exclusively with the static
 * {@code X-Admin-Api-Key} header (handled by {@link AdminApiKeyAuthenticationWebFilter}); the
 * {@code SecurityConfig} {@code SCOPE_tenant.config.write} URL rule and the {@code @PreAuthorize} on
 * the handlers remain as defence in depth, satisfied by the API-key filter. A bearer JWT alone (no
 * API key) on an {@code /admin/**} path is rejected with 401. Also covers SEC-B1 — the
 * {@code schemaName} path-variable validation.
 *
 * <p>The configured test key is supplied via an {@link AdminProperties} stub bean. The fail-closed
 * behaviour when {@code ebw.admin.api-key} is blank (<em>every</em> {@code /admin/**} request
 * rejected with 401) is verified in {@code WalletTenantConfigAdminEndpointBlankKeyIT}.
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
@Import({SecurityConfig.class, JwtAuthenticationWebFilter.class, AdminApiKeyAuthenticationWebFilter.class,
        WalletTenantConfigAdminEndpointIT.StubBeans.class})
@Tag("integration")
class WalletTenantConfigAdminEndpointIT {

    private static final String TEST_API_KEY = "test-admin-key-1234567890";
    private static final String WRONG_API_KEY = "wrong-admin-key";
    private static final String API_KEY_HEADER = "X-Admin-Api-Key";

    private static final String SOME_BEARER = "any-bearer-token";

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
        AdminProperties adminProperties() {
            return new AdminProperties(TEST_API_KEY);
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
                    if (SOME_BEARER.equals(token)) {
                        return Map.of(
                                "sub", UUID.randomUUID().toString(),
                                "email", "user@example.com");
                    }
                    throw new InvalidTokenException("unknown test token");
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
    // SEC-B2: /admin/** requires the X-Admin-Api-Key header
    // ------------------------------------------------------------------

    @Test
    void postWithoutApiKeyReturns401() {
        webTestClient.post().uri("/admin/wallet-tenant-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("urn:eudistack:error:admin-auth-required")
                .jsonPath("$.status").isEqualTo(401);
    }

    @Test
    void postWithWrongApiKeyReturns401() {
        webTestClient.post().uri("/admin/wallet-tenant-config")
                .header(API_KEY_HEADER, WRONG_API_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.type").isEqualTo("urn:eudistack:error:admin-auth-required");
    }

    @Test
    void postWithBearerJwtButNoApiKeyReturns401() {
        // A valid bearer JWT alone is NOT accepted on /admin/** — the API key is mandatory there.
        webTestClient.post().uri("/admin/wallet-tenant-config")
                .header("Authorization", "Bearer " + SOME_BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.type").isEqualTo("urn:eudistack:error:admin-auth-required");
    }

    @Test
    void postWithValidApiKeyReturns201() {
        stubWriterReturnsBrowserDescriptor();

        webTestClient.post().uri("/admin/wallet-tenant-config")
                .header(API_KEY_HEADER, TEST_API_KEY)
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
    void putWithValidApiKeyReturns200() {
        stubWriterReturnsBrowserDescriptor();

        webTestClient.put().uri("/admin/wallet-tenant-config/acme_bw")
                .header(API_KEY_HEADER, TEST_API_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.schema_name").isEqualTo("acme_bw");
    }

    @Test
    void putWithoutApiKeyReturns401() {
        webTestClient.put().uri("/admin/wallet-tenant-config/acme_bw")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ------------------------------------------------------------------
    // SEC-B1: malicious schemaName path variable → 400 (never reaches the writer).
    // The valid API key authenticates the request; the @Pattern on the path variable rejects it.
    // ------------------------------------------------------------------

    @Test
    void putWithMaliciousSchemaNameReturns400() {
        webTestClient.put().uri(uriBuilder -> uriBuilder
                        .path("/admin/wallet-tenant-config/{schemaName}")
                        .build("x_business_wallet.victim_business_wallet"))
                .header(API_KEY_HEADER, TEST_API_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void putWithUppercaseSchemaNameReturns400() {
        webTestClient.put().uri("/admin/wallet-tenant-config/DROP")
                .header(API_KEY_HEADER, TEST_API_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isBadRequest();
    }

    // ------------------------------------------------------------------
    // The new filter must not interfere with non-/admin/** paths.
    // ------------------------------------------------------------------

    @Test
    void wellKnownDiscoveryEndpointIsNotRejectedByAdminFilter() {
        // /.well-known/wallet-tenant-config is permitAll and is not an /admin/** path — the
        // admin filter passes it through untouched (there is no discovery controller in this slice,
        // so it never gets to a handler; what matters is that it is NOT a 401 admin-auth rejection).
        webTestClient.get().uri("/.well-known/wallet-tenant-config")
                .header("Host", "acme.eudiw.example.com")
                .exchange()
                .expectStatus().value(status -> org.assertj.core.api.Assertions.assertThat(status)
                        .as("the admin filter must not 401 a non-/admin/** path")
                        .isNotEqualTo(401));
    }

    @Test
    void publicAuthEndpointIsNotRejectedByAdminFilter() {
        // POST /api/v1/auth/register is permitAll and is not an /admin/** path — the admin filter
        // is a no-op (no auth controller in this slice; what matters is it is NOT a 401 rejection).
        webTestClient.post().uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().value(status -> org.assertj.core.api.Assertions.assertThat(status)
                        .as("the admin filter must not 401 a non-/admin/** path")
                        .isNotEqualTo(401));
    }
}
