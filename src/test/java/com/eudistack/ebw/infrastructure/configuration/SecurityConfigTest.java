package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.infrastructure.security.JwtAuthenticationWebFilter;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityConfigTest {

    @Test
    void corsConfigurationSource_usesAsteriskOrigin() {
        JwtAuthenticationWebFilter filter = mock(JwtAuthenticationWebFilter.class);

        SecurityConfig config = new SecurityConfig(filter);
        CorsConfigurationSource source = config.corsConfigurationSource();

        ServerWebExchange exchange = mock(ServerWebExchange.class);
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        RequestPath requestPath = mock(RequestPath.class);
        when(exchange.getRequest()).thenReturn(request);
        when(request.getPath()).thenReturn(requestPath);
        when(requestPath.pathWithinApplication()).thenReturn(PathContainer.parsePath("/"));

        CorsConfiguration corsConfig = source.getCorsConfiguration(exchange);

        assertNotNull(corsConfig);
        assertEquals(List.of("*"), corsConfig.getAllowedOriginPatterns());
        assertTrue(corsConfig.getAllowCredentials());
    }
}
