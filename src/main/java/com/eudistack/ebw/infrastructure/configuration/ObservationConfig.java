package com.eudistack.ebw.infrastructure.configuration;

import io.micrometer.common.KeyValue;
import io.micrometer.observation.ObservationFilter;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Observation setup. CustomObservationHandler is not registered here: Spring Boot already adds
 * every ObservationHandler bean to the registry, and registering it again runs it twice.
 */
@Configuration
public class ObservationConfig {

    /**
     * Registers the AOP aspect to enable the use of @Observed.
     * Spring Boot auto-configures and injects the base ObservationRegistry.
     */
    @Bean
    public ObservedAspect observedAspect(ObservationRegistry observationRegistry) {
        return new ObservedAspect(observationRegistry);
    }

    /** Tags every observation (spans and the metrics derived from it) with the component. */
    @Bean
    public ObservationFilter globalObservationFilter() {
        return context -> context.addLowCardinalityKeyValue(
                KeyValue.of("component", MicrometerMetricsConfig.COMPONENT));
    }
}
