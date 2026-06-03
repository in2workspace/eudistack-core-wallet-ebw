package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "ebw.cors")
public record CorsProperties(
        String allowedOrigins,
        String originsPath
) {
}
