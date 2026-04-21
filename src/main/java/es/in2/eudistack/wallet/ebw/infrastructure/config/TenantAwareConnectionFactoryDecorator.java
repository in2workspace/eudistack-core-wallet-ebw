package es.in2.eudistack.wallet.ebw.infrastructure.config;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryMetadata;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

import java.io.Closeable;

import static es.in2.eudistack.wallet.ebw.infrastructure.config.TenantDomainWebFilter.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Wraps the R2DBC ConnectionFactory with schema-per-tenant isolation
 * using {@code SET search_path TO <tenant>, public}.
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
public class TenantAwareConnectionFactoryDecorator {

    static final String SYSTEM_TENANT = "*";

    @Bean
    static BeanPostProcessor tenantAwareConnectionFactoryPostProcessor() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if ("connectionFactory".equals(beanName) && bean instanceof ConnectionFactory cf) {
                    log.info("EBW: Wrapping ConnectionFactory with schema-per-tenant decorator");
                    return new TenantAwareConnectionFactory(cf);
                }
                return bean;
            }
        };
    }

    static class TenantAwareConnectionFactory implements ConnectionFactory, Closeable {

        private final ConnectionFactory delegate;

        TenantAwareConnectionFactory(ConnectionFactory delegate) {
            this.delegate = delegate;
        }

        @Override
        public Publisher<? extends Connection> create() {
            return Mono.deferContextual(ctx -> {
                String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
                return Mono.from(delegate.create())
                        .flatMap(connection -> setSearchPath(connection, tenant));
            });
        }

        @Override
        public ConnectionFactoryMetadata getMetadata() {
            return delegate.getMetadata();
        }

        public void dispose() {
            if (delegate instanceof Closeable c) {
                try { c.close(); } catch (Exception e) {
                    log.warn("Error closing delegate ConnectionFactory: {}", e.getMessage());
                }
            }
        }

        @Override
        public void close() { dispose(); }

        private Mono<Connection> setSearchPath(Connection connection, String tenant) {
            String searchPath = SYSTEM_TENANT.equals(tenant) ? "public" : sanitize(tenant) + ", public";
            return Mono.from(connection.createStatement("SET search_path TO " + searchPath).execute())
                    .then(Mono.just(connection))
                    .doOnSuccess(c -> log.trace("EBW R2DBC search_path set to '{}'", searchPath))
                    .onErrorResume(e -> {
                        log.warn("EBW: Failed to set search_path: {}", e.getMessage());
                        return Mono.from(connection.close()).then(Mono.error(e));
                    });
        }

        private String sanitize(String tenant) {
            if (tenant == null || !tenant.matches("^[a-zA-Z0-9_-]+$")) {
                throw new IllegalArgumentException("Invalid tenant schema name: " + tenant);
            }
            return tenant;
        }
    }
}
