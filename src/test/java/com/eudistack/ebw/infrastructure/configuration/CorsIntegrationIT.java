package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.adapter.properties.CorsProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.SecurityProperties;
import com.eudistack.ebw.infrastructure.security.CorsOriginsLoader;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationWebFilter;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import com.eudistack.ebw.wallet.profile.infrastructure.web.WalletProfileQueryController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.reactive.HttpHandlerAutoConfiguration;
import org.springframework.boot.autoconfigure.web.reactive.ReactiveWebServerFactoryAutoConfiguration;
import org.springframework.boot.autoconfigure.web.reactive.WebFluxAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;


/**
 * Integration test for CORS configuration.
 * Verifies that CorsWebFilter with HIGHEST_PRECEDENCE correctly handles
 * preflight and actual requests based on the allowed origins list.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = {
        SecurityConfig.class,
        CorsFilterConfig.class,
        CorsOriginsLoader.class,
        JwtAuthenticationWebFilter.class,
        WalletProfileQueryController.class,
        WebFluxAutoConfiguration.class,
        JacksonAutoConfiguration.class,
        ReactiveSecurityAutoConfiguration.class,
        ReactiveWebServerFactoryAutoConfiguration.class,
        HttpHandlerAutoConfiguration.class
    },
    properties = {
        "ebw.cors.allowed-origins=http://localhost:4200",
        "ebw.security.max-payload-size=10485760"
    }
)
@EnableConfigurationProperties({CorsProperties.class, SecurityProperties.class, RateLimitProperties.class})
@ActiveProfiles("test")
class CorsIntegrationIT {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private TokenSigner tokenSigner;

    @MockitoBean
    private WalletProfileQueryPort walletProfileQueryPort;

    @MockitoBean
    private WalletProfileQueryTelemetry walletProfileQueryTelemetry;

    private static final String WELL_KNOWN_PATH = "/.well-known/openid-credential-issuer";
    private static final String ALLOWED_ORIGIN = "http://localhost:4200";

    @Test
    void optionsRequest_FromAllowedOrigin_ReturnsCorsHeaders() {
        webTestClient.options()
                .uri(WELL_KNOWN_PATH)
                .header("Origin", ALLOWED_ORIGIN)
                .header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", "Api-Version, Content-Type")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
                .expectHeader().valueEquals("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
                .expectHeader().valueMatches("Access-Control-Allow-Headers", ".*Api-Version.*")
                .expectHeader().doesNotExist("Access-Control-Allow-Credentials");
    }

    @Test
    void optionsRequest_FromDisallowedOrigin_ReturnsForbidden() {
        String disallowedOrigin = "https://malicious.com";

        webTestClient.options()
                .uri(WELL_KNOWN_PATH)
                .header("Origin", disallowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void optionsRequest_FromLocalhost4200_ReturnsCorsHeaders() {
        String allowedOrigin = "http://localhost:4200";

        webTestClient.options()
                .uri("/oid4vci/v1/authorize")
                .header("Origin", allowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", allowedOrigin);
    }
}
