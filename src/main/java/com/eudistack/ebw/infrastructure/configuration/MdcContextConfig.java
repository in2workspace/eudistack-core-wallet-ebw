package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import io.micrometer.context.ContextRegistry;
import io.micrometer.context.ThreadLocalAccessor;
import jakarta.annotation.PostConstruct;
import org.slf4j.MDC;
import org.springframework.context.annotation.Configuration;

/**
 * Registers a {@link ThreadLocalAccessor} that bridges the Reactor context key {@code tenantDomain}
 * with the SLF4J {@link MDC}. With {@code Hooks.enableAutomaticContextPropagation()} (in
 * {@link ReactorContextPropagationConfig}), the tenant is in the MDC on every operator, across
 * threads: the console pattern prints it, the OTLP appender exports it with the other MDC
 * attributes, and the observation filter reads it.
 *
 * <p>The accessor key must match the Reactor context key and the MDC key ({@code tenantDomain}).
 */
@Configuration(proxyBeanMethods = false)
public class MdcContextConfig {

    @PostConstruct
    public void registerTenantDomainAccessor() {
        ContextRegistry.getInstance().registerThreadLocalAccessor(
                new MdcThreadLocalAccessor(ReactorContextKeys.TENANT_DOMAIN));
    }

    /** Reads and writes a single MDC key as if it were a {@link ThreadLocal}. */
    static final class MdcThreadLocalAccessor implements ThreadLocalAccessor<String> {

        private final String key;

        MdcThreadLocalAccessor(String key) {
            this.key = key;
        }

        @Override
        public Object key() {
            return key;
        }

        @Override
        public String getValue() {
            return MDC.get(key);
        }

        @Override
        public void setValue(String value) {
            MDC.put(key, value);
        }

        @Override
        public void setValue() {
            MDC.remove(key);
        }
    }
}
