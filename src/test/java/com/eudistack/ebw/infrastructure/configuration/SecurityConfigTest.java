package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.eudistack.ebw.infrastructure.security.CorsOriginsLoader;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationWebFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityConfigTest {

    @Test
    void corsConfigurationSource_loadedOrigins_noWildcardAndWalletRequestHeaderAllowed() {
        // Arrange
        var loader = mock(CorsOriginsLoader.class);
        when(loader.loadOrigins()).thenReturn(List.of("https://sandbox.stg.eudistack.net"));
        var config = new SecurityConfig(mock(JwtAuthenticationWebFilter.class), loader,
                new RefreshCookies(), new ObjectMapper());
        var exchange = mock(ServerWebExchange.class);
        var request = mock(ServerHttpRequest.class);
        var requestPath = mock(RequestPath.class);
        when(exchange.getRequest()).thenReturn(request);
        when(request.getPath()).thenReturn(requestPath);
        when(requestPath.pathWithinApplication()).thenReturn(PathContainer.parsePath("/"));

        // Act
        var corsConfig = config.corsConfigurationSource().getCorsConfiguration(exchange);

        // Assert
        assertThat(corsConfig).isNotNull();
        assertThat(corsConfig.getAllowedOrigins()).containsExactly("https://sandbox.stg.eudistack.net");
        assertThat(corsConfig.getAllowedOriginPatterns()).isNull();
        assertThat(corsConfig.getAllowedHeaders()).contains("X-Wallet-Request", "Authorization");
        assertThat(corsConfig.getAllowCredentials()).isTrue();
    }
}
