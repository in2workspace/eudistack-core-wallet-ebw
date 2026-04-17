package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "ebw.encryption")
public record EncryptionProperties(
        String keyPath,
        String key
) {}
