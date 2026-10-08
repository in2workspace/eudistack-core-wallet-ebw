package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.infrastructure.security.CorsOriginsLoader;
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

    private ServerWebExchange mockExchange() {
        ServerWebExchange exchange = mock(ServerWebExchange.class);
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        RequestPath requestPath = mock(RequestPath.class);
        when(exchange.getRequest()).thenReturn(request);
        when(request.getPath()).thenReturn(requestPath);
        when(requestPath.pathWithinApplication()).thenReturn(PathContainer.parsePath("/"));
        return exchange;
    }

    @Test
    void corsConfigurationSource_usesLoaderOrigins() {
        CorsOriginsLoader loader = mock(CorsOriginsLoader.class);
        JwtAuthenticationWebFilter filter = mock(JwtAuthenticationWebFilter.class);
        when(loader.loadOrigins()).thenReturn(List.of("https://trusted.com"));

        SecurityConfig config = new SecurityConfig(filter, loader);
        CorsConfigurationSource source = config.corsConfigurationSource();
        CorsConfiguration corsConfig = source.getCorsConfiguration(mockExchange());

        assertNotNull(corsConfig);
        assertEquals(List.of("https://trusted.com"), corsConfig.getAllowedOriginPatterns());
        assertFalse(corsConfig.getAllowCredentials());
    }

    @Test
    void corsConfigurationSource_allowsMultipleConfiguredOrigins() {
        CorsOriginsLoader loader = mock(CorsOriginsLoader.class);
        JwtAuthenticationWebFilter filter = mock(JwtAuthenticationWebFilter.class);
        when(loader.loadOrigins()).thenReturn(List.of(
            "https://sandbox.eudistack.net",
            "https://kpmg.eudistack.net"
        ));

        SecurityConfig config = new SecurityConfig(filter, loader);
        CorsConfigurationSource source = config.corsConfigurationSource();
        CorsConfiguration corsConfig = source.getCorsConfiguration(mockExchange());

        assertNotNull(corsConfig);
        assertEquals(2, corsConfig.getAllowedOriginPatterns().size());
        assertFalse(corsConfig.getAllowCredentials());
    }

    @Test
    void corsConfigurationSource_rejectsUnconfiguredOrigin() {
        CorsOriginsLoader loader = mock(CorsOriginsLoader.class);
        JwtAuthenticationWebFilter filter = mock(JwtAuthenticationWebFilter.class);
        when(loader.loadOrigins()).thenReturn(List.of("https://sandbox.eudistack.net"));

        SecurityConfig config = new SecurityConfig(filter, loader);
        CorsConfigurationSource source = config.corsConfigurationSource();
        CorsConfiguration corsConfig = source.getCorsConfiguration(mockExchange());

        assertNull(corsConfig.checkOrigin("https://evil.example.com"));
    }

    @Test
    void corsConfigurationSource_emptyOriginsBlocksAll() {
        CorsOriginsLoader loader = mock(CorsOriginsLoader.class);
        JwtAuthenticationWebFilter filter = mock(JwtAuthenticationWebFilter.class);
        when(loader.loadOrigins()).thenReturn(List.of());

        SecurityConfig config = new SecurityConfig(filter, loader);
        CorsConfigurationSource source = config.corsConfigurationSource();
        CorsConfiguration corsConfig = source.getCorsConfiguration(mockExchange());

        assertNull(corsConfig.checkOrigin("https://anything.com"));
    }

    @Test
    void corsConfigurationSource_allowedMethodsAndHeaders() {
        CorsOriginsLoader loader = mock(CorsOriginsLoader.class);
        JwtAuthenticationWebFilter filter = mock(JwtAuthenticationWebFilter.class);
        when(loader.loadOrigins()).thenReturn(List.of("https://trusted.com"));

        SecurityConfig config = new SecurityConfig(filter, loader);
        CorsConfigurationSource source = config.corsConfigurationSource();
        CorsConfiguration corsConfig = source.getCorsConfiguration(mockExchange());

        assertEquals(
            List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),
            corsConfig.getAllowedMethods()
        );
        assertEquals(
            List.of("Authorization", "Content-Type", "Api-Version"),
            corsConfig.getAllowedHeaders()
        );
        assertEquals(3600L, corsConfig.getMaxAge());
    }
}
