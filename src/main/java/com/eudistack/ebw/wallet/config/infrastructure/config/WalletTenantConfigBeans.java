package com.eudistack.ebw.wallet.config.infrastructure.config;

import com.eudistack.ebw.wallet.config.domain.port.ConfigurationAuditPort;
import com.eudistack.ebw.wallet.config.domain.port.DiscoveryCacheInvalidationPort;
import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import com.eudistack.ebw.wallet.config.domain.service.TenantWalletConfigInvariants;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.cloudfront.CloudFrontInvalidationAdapter;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.PublicSchemaConnectionFactory;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.TenantConfigAuditR2dbcAdapter;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.WalletTenantConfigR2dbcAdapter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.r2dbc.core.DatabaseClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudfront.CloudFrontAsyncClient;

/**
 * Spring bean definitions for the {@code wallet.config} bounded context.
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
 * {@code SpringWalletCredentialRepository}). Therefore the two
 * {@code search_path = public} templates required by this bounded context are
 * built as <em>plain objects</em> inside the adapter factory methods below — they
 * never become Spring beans and the auto-configuration stays intact.
 *
 * <p>Both templates wrap the primary {@link ConnectionFactory} bean (already
 * decorated by {@code TenantAwareConnectionFactoryDecorator}) with a
 * {@link PublicSchemaConnectionFactory} that issues {@code SET search_path TO public}
 * on every acquired connection, overriding any tenant-specific search_path. This
 * keeps the discovery read path and the admin write path pinned to the
 * {@code public.tenant_wallet_config} table (AD-1, AD-S2). The audit adapter
 * still targets {@code <schema>_business_wallet.wallet_config_audit} via explicit
 * schema-qualified table names, so it is unaffected by the fixed search_path.
 *
 * <p>{@code WalletTenantConfigReadService} and {@code TenantWalletConfigurationWriter}
 * are {@code @Service}-annotated and discovered via component scan — no explicit
 * {@code @Bean} declarations are needed for them.
 */
@Configuration
@EnableConfigurationProperties(CloudFrontProperties.class)
public class WalletTenantConfigBeans {

    private static final String READ_POOL_LABEL = "publicSchema";
    private static final String WRITE_POOL_LABEL = "publicSchemaRw";

    // ------------------------------------------------------------------
    // Domain service
    // ------------------------------------------------------------------

    @Bean
    public TenantWalletConfigInvariants tenantWalletConfigInvariants() {
        return new TenantWalletConfigInvariants();
    }

    // ------------------------------------------------------------------
    // Persistence adapter — TenantConfigurationPort (Tasks 4 + 5)
    // ------------------------------------------------------------------

    /**
     * R2DBC adapter for the discovery plane. The read template is backed by a
     * {@code search_path = public} pool ({@code publicSchema}); the write template
     * by a second {@code search_path = public} pool ({@code publicSchemaRw}). Both
     * wrap the primary tenant-aware {@link ConnectionFactory}.
     */
    @Bean
    public TenantConfigurationPort tenantConfigurationPort(ConnectionFactory connectionFactory) {
        R2dbcEntityTemplate readTemplate = publicSchemaTemplate(connectionFactory, READ_POOL_LABEL);
        R2dbcEntityTemplate writeTemplate = publicSchemaTemplate(connectionFactory, WRITE_POOL_LABEL);
        return new WalletTenantConfigR2dbcAdapter(readTemplate, writeTemplate);
    }

    // ------------------------------------------------------------------
    // Audit adapter — ConfigurationAuditPort (Task 5)
    // ------------------------------------------------------------------

    /**
     * Append-only audit adapter writing to {@code <schemaName>_business_wallet.wallet_config_audit}.
     *
     * <p>Uses a {@link DatabaseClient} from the {@code publicSchemaRw} pool. The
     * target table is always referenced with an explicit schema qualifier, so the
     * fixed {@code search_path = public} does not affect routing (AD-S2).
     */
    @Bean
    public ConfigurationAuditPort configurationAuditPort(ConnectionFactory connectionFactory,
                                                         ObjectMapper objectMapper) {
        DatabaseClient databaseClient =
                publicSchemaTemplate(connectionFactory, WRITE_POOL_LABEL).getDatabaseClient();
        return new TenantConfigAuditR2dbcAdapter(databaseClient, objectMapper);
    }

    // ------------------------------------------------------------------
    // CloudFront adapter — DiscoveryCacheInvalidationPort (Task 5)
    // ------------------------------------------------------------------

    /**
     * AWS CloudFront async client (SDK v2).
     *
     * <p>CloudFront is a global service, so the region is pinned to {@link Region#AWS_GLOBAL}.
     * This keeps client construction independent of the ambient region-provider chain
     * (which would otherwise fail fast in local / CI environments that have no AWS
     * region configured). Credentials are still resolved lazily by the default
     * credentials chain on the first API call.
     */
    @Bean
    public CloudFrontAsyncClient cloudFrontAsyncClient() {
        return CloudFrontAsyncClient.builder().region(Region.AWS_GLOBAL).build();
    }

    /**
     * Cache invalidation adapter wired with the CloudFront client and distribution ID.
     *
     * <p>The distribution ID is injected from {@code ebw.cloudfront.distribution-id}
     * ({@code CLOUDFRONT_DISTRIBUTION_ID} env var in ECS). If the property is blank
     * (local / CI environments), invalidation calls fail gracefully — the adapter
     * retries with exponential backoff and then records a {@code CACHE_INVALIDATION_FAILED}
     * audit entry; the originating write is never rolled back (AD-S3).
     */
    @Bean
    public DiscoveryCacheInvalidationPort discoveryCacheInvalidationPort(
            CloudFrontAsyncClient cloudFrontClient,
            CloudFrontProperties cloudFrontProperties) {
        return new CloudFrontInvalidationAdapter(cloudFrontClient, cloudFrontProperties.distributionId());
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

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
