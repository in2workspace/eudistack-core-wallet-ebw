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
import com.eudistack.ebw.wallet.config.application.workflow.TenantWalletConfigurationWriter;
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

import java.util.Map;

/**
 * Fail-closed variant of {@link WalletTenantConfigAdminEndpointIT}: when {@code ebw.admin.api-key}
 * ({@code ADMIN_API_KEY}) is blank, <em>every</em> {@code /admin/**} request is rejected with HTTP
 * 401 — there is no implicit "no key configured ⇒ open" mode (SEC-B2).
 *
 * <p>Kept in its own class because the configured key is a constructor-time choice of the
 * {@link AdminApiKeyAuthenticationWebFilter} singleton, so it cannot vary within one application
 * context.
 *
 * <p>Tagged {@code integration} (consistent with the other admin-controller tests).
 */
@WebFluxTest(controllers = WalletTenantConfigAdminController.class,
        excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE,
                classes = {PayloadSizeLimitWebFilter.class, RateLimitWebFilter.class,
                        TenantDomainWebFilter.class}))
@Import({SecurityConfig.class, JwtAuthenticationWebFilter.class, AdminApiKeyAuthenticationWebFilter.class,
        WalletTenantConfigAdminEndpointBlankKeyIT.StubBeans.class})
@Tag("integration")
class WalletTenantConfigAdminEndpointBlankKeyIT {

    private static final String API_KEY_HEADER = "X-Admin-Api-Key";

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

        /** Blank key → fail-closed. */
        @Bean
        AdminProperties adminProperties() {
            return new AdminProperties("");
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
                    throw new InvalidTokenException("unknown test token");
                }
            };
        }
    }

    @Test
    void postWithAnyApiKeyReturns401WhenKeyUnconfigured() {
        webTestClient.post().uri("/admin/wallet-tenant-config")
                .header(API_KEY_HEADER, "anything")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.type").isEqualTo("urn:eudistack:error:admin-auth-required");
    }

    @Test
    void postWithoutApiKeyReturns401WhenKeyUnconfigured() {
        webTestClient.post().uri("/admin/wallet-tenant-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.type").isEqualTo("urn:eudistack:error:admin-auth-required");
    }
}
