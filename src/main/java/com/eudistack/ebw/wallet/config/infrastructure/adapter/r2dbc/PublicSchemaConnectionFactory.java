package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryMetadata;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * {@link ConnectionFactory} decorator that fixes {@code search_path = public}
 * on every connection before returning it to the caller.
 *
 * <p>Unlike {@code TenantAwareConnectionFactoryDecorator}, which reads the tenant
 * from the Reactor context and sets the schema dynamically, this decorator is
 * stateless and always sets {@code search_path = public}. It is used exclusively
 * for the discovery read path and the admin write path that operate on the
 * {@code public.tenant_wallet_config} table (AD-1, AD-S2).
 *
 * <p>This class wraps the underlying R2DBC pool (which is the tenant-aware
 * {@code connectionFactory} bean). However, because each connection is immediately
 * overridden with {@code SET search_path = public}, the tenant-aware post-processing
 * that may have already set a different {@code search_path} is overwritten.
 * In practice this works correctly because:
 * <ol>
 *   <li>The {@code TenantAwareConnectionFactory} wraps the raw pool and sets
 *       {@code search_path} per-request based on the Reactor context.
 *   <li>This decorator is constructed with the underlying raw pool (before wrapping)
 *       by being declared as a separate {@code @Bean} that receives the
 *       {@code @Qualifier("rawConnectionFactory")} — see
 *       {@code WalletTenantConfigBeans}.
 * </ol>
 */
public class PublicSchemaConnectionFactory implements ConnectionFactory {

    private static final Logger log = LoggerFactory.getLogger(PublicSchemaConnectionFactory.class);

    private final ConnectionFactory delegate;
    private final String label;

    public PublicSchemaConnectionFactory(ConnectionFactory delegate, String label) {
        this.delegate = delegate;
        this.label = label;
    }

    @Override
    public Publisher<? extends Connection> create() {
        return Mono.from(delegate.create())
                .flatMap(connection ->
                        Mono.from(connection.createStatement("SET search_path TO public").execute())
                                .then(Mono.just(connection))
                                .doOnSuccess(c -> log.trace("[{}] search_path fixed to 'public'", label))
                                .onErrorResume(e -> {
                                    log.warn("[{}] Failed to set search_path: {}", label, e.getMessage());
                                    return Mono.from(connection.close()).then(Mono.error(e));
                                }));
    }

    @Override
    public ConnectionFactoryMetadata getMetadata() {
        return delegate.getMetadata();
    }
}
