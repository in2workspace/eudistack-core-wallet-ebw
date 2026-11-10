package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.observability.ObservedTenants;
import io.micrometer.common.KeyValue;
import io.micrometer.observation.ObservationFilter;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Observation setup. CustomObservationHandler is not registered here: Spring Boot already adds
 * every ObservationHandler bean to the registry, and registering it again runs it twice.
 */
@Configuration
public class ObservationConfig {

    private static final String TENANT_TAG = "tenant";

    /**
     * Registers the AOP aspect to enable the use of @Observed.
     * Spring Boot auto-configures and injects the base ObservationRegistry.
     */
    @Bean
    public ObservedAspect observedAspect(ObservationRegistry observationRegistry) {
        return new ObservedAspect(observationRegistry);
    }

    /**
     * Tags every observation (spans and the metrics derived from it) with the component and tenant.
     * A tenant already on the observation stays: Micrometer applies the convention first, and
     * TenantServerRequestObservationConvention reads it from the exchange because the MDC is empty
     * by the time an HTTP observation stops. Only an active tenant becomes the tag.
     */
    @Bean
    public ObservationFilter globalObservationFilter(ObservedTenants observedTenants) {
        return context -> {
            context.addLowCardinalityKeyValue(KeyValue.of("component", MicrometerMetricsConfig.COMPONENT));
            if (context.getLowCardinalityKeyValue(TENANT_TAG) == null) {
                context.addLowCardinalityKeyValue(KeyValue.of(TENANT_TAG,
                        observedTenants.tagValue(MDC.get(ReactorContextKeys.TENANT_DOMAIN))));
            }
            return context;
        };
    }
}
