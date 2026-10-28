package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.infrastructure.observability.CustomObservationHandler;
import io.micrometer.common.KeyValue;
import io.micrometer.observation.ObservationFilter;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import org.springframework.boot.actuate.autoconfigure.observation.ObservationRegistryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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

    @Bean
    ObservationRegistryCustomizer<ObservationRegistry> registerCustomObservationHandler(
            CustomObservationHandler customObservationHandler) {
        return registry -> registry.observationConfig()
                .observationHandler(customObservationHandler);
    }
}
