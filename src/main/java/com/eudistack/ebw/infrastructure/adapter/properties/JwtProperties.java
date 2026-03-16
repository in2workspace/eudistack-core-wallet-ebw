package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "ebw.jwt")
public record JwtProperties(
        String privateKeyPath,
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        String issuer
) {
}
