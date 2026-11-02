package com.eudistack.ebw.infrastructure.configuration;

import io.micrometer.core.instrument.Clock;
import io.micrometer.registry.otlp.OtlpConfig;
import io.micrometer.registry.otlp.OtlpMeterRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Replaces Boot's OTLP/HTTP meter registry with one that exports over gRPC. Only when the export
 * is on: otherwise Boot creates no {@link OtlpConfig} and nothing is exported.
 */
@Configuration
@ConditionalOnProperty(name = "management.otlp.metrics.export.enabled", havingValue = "true")
public class OtlpGrpcMetricsConfig {

    @Bean
    public OtlpMeterRegistry otlpMeterRegistry(OtlpConfig otlpConfig, Clock clock) {
        return OtlpMeterRegistry.builder(otlpConfig)
                .clock(clock)
                .metricsSender(new OtlpGrpcMetricsSender())
                .build();
    }
}
