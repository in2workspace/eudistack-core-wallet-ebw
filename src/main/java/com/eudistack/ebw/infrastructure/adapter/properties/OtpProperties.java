package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "ebw.otp")
public record OtpProperties(
        int length,
        Duration expiration,
        int maxAttempts
) {
}
