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

    @Test
    void corsConfigurationSource_usesLoaderOrigins() throws Exception {
        CorsOriginsLoader loader = mock(CorsOriginsLoader.class);
        JwtAuthenticationWebFilter filter = mock(JwtAuthenticationWebFilter.class);
        when(loader.loadOrigins()).thenReturn(List.of("https://trusted.com"));

        SecurityConfig config = new SecurityConfig(filter, loader);

        // corsConfigurationSource is private, use reflection to test it
        java.lang.reflect.Method method = SecurityConfig.class.getDeclaredMethod("corsConfigurationSource");
        method.setAccessible(true);
        CorsConfigurationSource source = (CorsConfigurationSource) method.invoke(config);

        ServerWebExchange exchange = mock(ServerWebExchange.class);
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        RequestPath requestPath = mock(RequestPath.class);
        when(exchange.getRequest()).thenReturn(request);
        when(request.getPath()).thenReturn(requestPath);
        when(requestPath.pathWithinApplication()).thenReturn(PathContainer.parsePath("/"));

        CorsConfiguration corsConfig = source.getCorsConfiguration(exchange);

        assertNotNull(corsConfig);
        assertEquals(List.of("https://trusted.com"), corsConfig.getAllowedOriginPatterns());
        assertTrue(corsConfig.getAllowCredentials());
    }
}
