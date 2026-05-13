package com.eudistack.ebw.wallet.config.infrastructure.config;

import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.PublicSchemaConnectionFactory;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.WalletTenantConfigR2dbcAdapter;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.r2dbc.core.DatabaseClient;

/**
 * Spring bean definitions for the {@code wallet.config} bounded context (read-only discovery path).
 *
 * <p><strong>Why this class declares no extra {@code ConnectionFactory} or
 * {@code R2dbcEntityTemplate} beans.</strong> Spring Boot's R2DBC
 * auto-configuration ({@code R2dbcAutoConfiguration} / {@code R2dbcDataAutoConfiguration})
 * and Spring Data R2DBC repository scanning rely on there being exactly one
 * {@code ConnectionFactory} bean and one auto-configured {@code R2dbcEntityTemplate}.
 * Publishing additional beans of those types makes {@code R2dbcAutoConfiguration#databaseClient}
 * unable to resolve a unique {@code ConnectionFactory} and makes
 * {@code R2dbcDataAutoConfiguration#r2dbcEntityTemplate} back off (it is
 * {@code @ConditionalOnMissingBean}), which in turn prevents Spring Data from
 * instantiating the application's reactive repositories (e.g.
 * {@code SpringWalletCredentialRepository}). Therefore the {@code search_path = public}
 * template required by this bounded context is built as a <em>plain object</em> inside the
 * adapter factory method below — it never becomes a Spring bean and the auto-configuration
 * stays intact.
 *
 * <p>The template wraps the primary {@link ConnectionFactory} bean (already
 * decorated by {@code TenantAwareConnectionFactoryDecorator}) with a
 * {@link PublicSchemaConnectionFactory} that issues {@code SET search_path TO public}
 * on every acquired connection, overriding any tenant-specific search_path. This
 * keeps the discovery read path pinned to the {@code public.tenant_wallet_config}
 * table (AD-1, AD-S2).
 *
 * <p>{@code WalletTenantConfigReadService} is {@code @Service}-annotated and discovered via
 * component scan — no explicit {@code @Bean} declaration is needed for it.
 *
 * <p>The discovery-plane <em>write</em> path (admin endpoint, single transactional writer,
 * optimistic lock, audit adapter, targeted CloudFront invalidation, and the second
 * {@code @Qualifier("publicSchemaRw")} pool) moved to EUDISTACK-55.
 */
@Configuration
public class WalletTenantConfigBeans {

    private static final String READ_POOL_LABEL = "publicSchema";

    /**
     * Read-only R2DBC adapter for the discovery plane. The read template is backed by a
     * {@code search_path = public} pool ({@code publicSchema}) wrapping the primary tenant-aware
     * {@link ConnectionFactory}.
     */
    @Bean
    public TenantConfigurationPort tenantConfigurationPort(ConnectionFactory connectionFactory) {
        R2dbcEntityTemplate readTemplate = publicSchemaTemplate(connectionFactory, READ_POOL_LABEL);
        return new WalletTenantConfigR2dbcAdapter(readTemplate);
    }

    /**
     * Builds a {@link R2dbcEntityTemplate} backed by a {@link PublicSchemaConnectionFactory}
     * wrapper over the primary {@link ConnectionFactory}. The result is a plain object
     * (NOT a Spring bean) so Spring Boot's R2DBC auto-configuration is unaffected — see
     * the class-level Javadoc for the rationale.
     *
     * @param connectionFactory the primary (tenant-aware) connection factory bean
     * @param poolLabel         a human-readable label used only for trace logging
     * @return a ready-to-use {@link R2dbcEntityTemplate} whose connections always run with
     *         {@code search_path = public}
     */
    private static R2dbcEntityTemplate publicSchemaTemplate(ConnectionFactory connectionFactory, String poolLabel) {
        ConnectionFactory publicSchema = new PublicSchemaConnectionFactory(connectionFactory, poolLabel);
        DatabaseClient databaseClient = DatabaseClient.builder().connectionFactory(publicSchema).build();
        return new R2dbcEntityTemplate(databaseClient, new DefaultReactiveDataAccessStrategy(PostgresDialect.INSTANCE));
    }
}
