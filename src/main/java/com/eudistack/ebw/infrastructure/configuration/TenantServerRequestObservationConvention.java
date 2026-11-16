package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.observability.ObservedTenants;
import io.micrometer.common.KeyValue;
import io.micrometer.common.KeyValues;
import org.springframework.http.server.reactive.observation.DefaultServerRequestObservationConvention;
import org.springframework.http.server.reactive.observation.ServerRequestObservationContext;
import org.springframework.stereotype.Component;

/**
 * Adds a {@code tenant} low-cardinality tag to the auto-configured {@code http.server.requests}
 * observation, so error rate and latency can be sliced per tenant. Registering this bean overrides
 * Boot's default convention ({@code @ConditionalOnMissingBean(ServerRequestObservationConvention.class)}).
 *
 * <p>Reads the tenant from the exchange attribute set by {@link TenantDomainWebFilter} rather than
 * the Reactor Context: by the time this convention runs (on observation stop), the Context is no
 * longer accessible. Only an active tenant becomes the tag, see {@link ObservedTenants}.
 */
@Component
public class TenantServerRequestObservationConvention extends DefaultServerRequestObservationConvention {

    static final String TENANT_TAG = "tenant";

    private final ObservedTenants observedTenants;

    public TenantServerRequestObservationConvention(ObservedTenants observedTenants) {
        this.observedTenants = observedTenants;
    }

    @Override
    public KeyValues getLowCardinalityKeyValues(ServerRequestObservationContext context) {
        return super.getLowCardinalityKeyValues(context).and(tenant(context));
    }

    private KeyValue tenant(ServerRequestObservationContext context) {
        Object tenant = context.getAttributes().get(ReactorContextKeys.TENANT_DOMAIN);
        return KeyValue.of(TENANT_TAG, observedTenants.tagValue(tenant instanceof String value ? value : null));
    }
}
