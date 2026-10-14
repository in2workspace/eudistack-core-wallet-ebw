package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.infrastructure.security.TenantCorsConfigurationSource;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link TenantCorsConfigurationSource}. */
class SecurityConfigTest {

    private final TenantCorsConfigurationSource source = new TenantCorsConfigurationSource(
            new TenantDomainWebFilter(true),
            tenant -> Map.of("sandbox", List.of("https://sandbox.stg.eudistack.net")).getOrDefault(tenant, List.of()),
            List.of("https://status.eudistack.net"));

    @Test
    void getCorsConfiguration_tenantRequest_admitsOnlyTheTenantOriginsWithCredentials() {
        // Arrange
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/refresh")
                .header("X-Tenant", "sandbox"));

        // Act
        var config = source.getCorsConfiguration(exchange);

        // Assert
        assertThat(config.getAllowedOrigins()).containsExactly("https://sandbox.stg.eudistack.net");
        assertThat(config.getAllowedOriginPatterns()).isNull();
        assertThat(config.getAllowedHeaders()).contains("X-Wallet-Request", "Authorization");
        assertThat(config.getAllowCredentials()).isTrue();
    }

    @Test
    void getCorsConfiguration_unknownTenant_admitsNoOrigin() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/refresh")
                .header("X-Tenant", "unknown"));

        assertThat(source.getCorsConfiguration(exchange).getAllowedOrigins()).isEmpty();
    }

    @Test
    void getCorsConfiguration_wellKnownPath_usesTheGlobalOrigins() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/.well-known/wallet-config-metadata"));

        assertThat(source.getCorsConfiguration(exchange).getAllowedOrigins())
                .containsExactly("https://status.eudistack.net");
    }
}
