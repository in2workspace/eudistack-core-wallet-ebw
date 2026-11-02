package com.eudistack.ebw.infrastructure.configuration;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.metrics.MeterRegistryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MicrometerMetricsConfig {

    static final String COMPONENT = "wallet-ebw";

    @Bean
    public MeterRegistryCustomizer<MeterRegistry> commonTagsCustomizer(
            @Value("${spring.application.name}") String appName) {
        return registry -> registry.config().commonTags(
                "application", appName,
                "component", COMPONENT
        );
    }
}
