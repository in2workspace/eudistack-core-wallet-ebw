package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "ebw.rate-limit")
public record RateLimitProperties(
        int registerPerEmail,
        int registerPerIp,
        int verifyPerEmail,
        int verifyPerIp,
        int refreshPerIp,
        int logoutPerIp,
        int hybridSignPerIp,
        Duration window
) {
}
