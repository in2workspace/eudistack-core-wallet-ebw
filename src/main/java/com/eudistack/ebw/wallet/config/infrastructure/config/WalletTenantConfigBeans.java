package com.eudistack.ebw.wallet.config.infrastructure.config;

import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import com.eudistack.ebw.wallet.config.domain.service.TenantWalletConfigInvariants;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.PublicSchemaConnectionFactory;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.WalletTenantConfigR2dbcAdapter;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.r2dbc.core.DatabaseClient;

/**
 * Spring bean definitions for the {@code wallet.config} bounded context.
 *
 * <p>Three logical connection pools are declared here (AD-S2):
 * <ol>
 *   <li>{@code publicSchema} — read-only {@link R2dbcEntityTemplate} backed by a
 *       {@link PublicSchemaConnectionFactory} decorator that fixes
 *       {@code search_path = public}. Used exclusively by the discovery read path.</li>
 *   <li>{@code publicSchemaRw} — read-write {@link R2dbcEntityTemplate} backed by
 *       a second {@link PublicSchemaConnectionFactory} decorator (also
 *       {@code search_path = public}). Declared here for completeness; wired into the
 *       write side in Task 5.</li>
 * </ol>
 *
 * <p>Both pools wrap the primary Spring Boot {@link ConnectionFactory} bean (which
 * is already wrapped by {@code TenantAwareConnectionFactoryDecorator} via a
 * {@code BeanPostProcessor}). The {@code PublicSchemaConnectionFactory} overrides
 * the tenant-aware search_path by issuing a second {@code SET search_path = public}
 * statement immediately on connection acquisition.
 *
 * <p>Domain services are plain objects — no framework annotations in the domain layer.
 */
@Configuration
public class WalletTenantConfigBeans {

    // ------------------------------------------------------------------
    // Domain service
    // ------------------------------------------------------------------

    @Bean
    public TenantWalletConfigInvariants tenantWalletConfigInvariants() {
        return new TenantWalletConfigInvariants();
    }

    // ------------------------------------------------------------------
    // R2DBC connection pool — discovery read path (public schema, read-only)
    // ------------------------------------------------------------------

    /**
     * Read-only connection factory whose {@code search_path} is always {@code public}.
     *
     * <p>Wraps the primary (tenant-aware) {@link ConnectionFactory} and overrides
     * the search_path with a dedicated {@code SET search_path = public} statement
     * on every acquired connection. The underlying pool is shared (no physical new pool)
     * but the effective schema is always {@code public} (KISS, AD-S2 §3.5).
     */
    @Bean
    @Qualifier("publicSchemaConnectionFactory")
    public ConnectionFactory publicSchemaConnectionFactory(ConnectionFactory connectionFactory) {
        return new PublicSchemaConnectionFactory(connectionFactory, "publicSchema");
    }

    /**
     * Read-write connection factory for the admin write path on the public schema.
     *
     * <p>Identical behaviour to {@code publicSchemaConnectionFactory} — both target
     * {@code search_path = public}. Declared as a separate bean so that the write
     * adapter (Task 5) can be granted independently and ArchUnit can verify the
     * correct qualifier is used in each adapter.
     */
    @Bean
    @Qualifier("publicSchemaRwConnectionFactory")
    public ConnectionFactory publicSchemaRwConnectionFactory(ConnectionFactory connectionFactory) {
        return new PublicSchemaConnectionFactory(connectionFactory, "publicSchemaRw");
    }

    // ------------------------------------------------------------------
    // R2DBC entity templates (one per pool)
    // ------------------------------------------------------------------

    @Bean
    @Qualifier("publicSchema")
    public R2dbcEntityTemplate publicSchemaEntityTemplate(
            @Qualifier("publicSchemaConnectionFactory") ConnectionFactory publicSchemaConnectionFactory) {
        var strategy = new DefaultReactiveDataAccessStrategy(PostgresDialect.INSTANCE);
        return new R2dbcEntityTemplate(
                DatabaseClient.builder().connectionFactory(publicSchemaConnectionFactory).build(),
                strategy);
    }

    @Bean
    @Qualifier("publicSchemaRw")
    public R2dbcEntityTemplate publicSchemaRwEntityTemplate(
            @Qualifier("publicSchemaRwConnectionFactory") ConnectionFactory publicSchemaRwConnectionFactory) {
        var strategy = new DefaultReactiveDataAccessStrategy(PostgresDialect.INSTANCE);
        return new R2dbcEntityTemplate(
                DatabaseClient.builder().connectionFactory(publicSchemaRwConnectionFactory).build(),
                strategy);
    }

    // ------------------------------------------------------------------
    // Persistence adapter — TenantConfigurationPort
    // ------------------------------------------------------------------

    @Bean
    public TenantConfigurationPort tenantConfigurationPort(
            @Qualifier("publicSchema") R2dbcEntityTemplate publicSchemaTemplate) {
        return new WalletTenantConfigR2dbcAdapter(publicSchemaTemplate);
    }

    // NOTE: WalletTenantConfigReadService and TenantWalletConfigurationWriter are
    // annotated with @Service and discovered via component scan — no explicit @Bean
    // declarations are needed here.
}
