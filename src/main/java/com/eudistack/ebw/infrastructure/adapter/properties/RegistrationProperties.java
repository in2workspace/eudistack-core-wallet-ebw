package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "ebw.registration")
public record RegistrationProperties(
        List<String> allowedEmailDomains
) {
    public RegistrationProperties {
        allowedEmailDomains = allowedEmailDomains == null ? List.of() : allowedEmailDomains;
    }
}
