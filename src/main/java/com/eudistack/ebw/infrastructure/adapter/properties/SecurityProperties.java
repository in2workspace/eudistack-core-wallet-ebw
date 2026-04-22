package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "ebw.security")
public record SecurityProperties(
        long maxPayloadSize
) {
}
