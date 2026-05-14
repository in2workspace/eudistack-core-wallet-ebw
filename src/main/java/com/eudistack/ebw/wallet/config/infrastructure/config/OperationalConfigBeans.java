package com.eudistack.ebw.wallet.config.infrastructure.config;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.kms.KmsEnvelopeEncryptionAdapter;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.probe.DbTdeProbeAdapter;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.probe.KeyManagerProbeRegistry;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.OperationalConfigAuditR2dbcAdapter;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.OperationalConfigR2dbcAdapter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.observation.ObservationRegistry;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.transaction.ReactiveTransactionManager;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

import java.time.Duration;
import java.util.Map;

import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW;

/**
 * Spring bean definitions for the operational configuration plane (EUDISTACK-414).
 *
 * <p>All adapters in this bounded context follow the same explicit-wiring pattern established by
 * {@link WalletTenantConfigBeans}: no {@code @Component} / {@code @Repository} annotations on
 * the adapter classes; all instances are constructed here with full constructor injection.
 * This keeps the dependency graph explicit and the context easy to reason about.
 *
 * <h2>Beans defined</h2>
 * <ul>
 *   <li>{@link OperationalConfigR2dbcAdapter} — primary R2DBC port (tenant-schema-aware).</li>
 *   <li>{@code auditTransactionalOperator} — {@link TransactionalOperator} with
 *       {@code PROPAGATION_REQUIRES_NEW} so audit rows persist independently of the outer
 *       writer transaction (AD-S4, AC-4b, AC-4c).</li>
 *   <li>{@link OperationalConfigAuditR2dbcAdapter} — audit port wired with the
 *       {@code auditTransactionalOperator}.</li>
 *   <li>{@link KmsEnvelopeEncryptionAdapter} — KMS envelope encryption port.</li>
 *   <li>{@link DbTdeProbeAdapter} — DB-TDE connectivity probe.</li>
 *   <li>{@link KeyManagerProbeRegistry} — registry dispatching probes by key manager.</li>
 * </ul>
 *
 * <h2>Application services</h2>
 * {@code OperationalConfigWriter} and {@code OperationalConfigReader} are annotated with
 * {@code @Service} and discovered via component scan — no explicit {@code @Bean} declaration
 * is needed for them.
 */
@Configuration
public class OperationalConfigBeans {

    /**
     * Primary R2DBC adapter for the operational config plane.
     *
     * <p>Uses the default (tenant-aware) {@link DatabaseClient}. All queries run against the
     * current tenant's schema because {@code TenantAwareConnectionFactoryDecorator} sets
     * {@code search_path} on each acquired connection (AD-1, AC-3a).
     *
     * @param databaseClient the auto-configured, tenant-aware client
     * @return the adapter exposing {@link com.eudistack.ebw.wallet.config.domain.port.OperationalConfigPort}
     */
    @Bean
    public OperationalConfigR2dbcAdapter operationalConfigR2dbcAdapter(DatabaseClient databaseClient) {
        return new OperationalConfigR2dbcAdapter(databaseClient);
    }

    /**
     * {@link TransactionalOperator} configured with {@code PROPAGATION_REQUIRES_NEW}.
     *
     * <p>Used exclusively by {@link OperationalConfigAuditR2dbcAdapter} so that every audit row
     * is committed in its own independent transaction — guaranteeing that DENY rows survive an
     * outer writer rollback and PERMIT rows are committed regardless of what follows (AD-S4).
     *
     * @param txManager the auto-configured reactive transaction manager
     * @return a {@link TransactionalOperator} with {@code REQUIRES_NEW} propagation
     */
    @Bean(name = "auditTransactionalOperator")
    public TransactionalOperator auditTransactionalOperator(ReactiveTransactionManager txManager) {
        DefaultTransactionDefinition definition = new DefaultTransactionDefinition();
        definition.setPropagationBehavior(PROPAGATION_REQUIRES_NEW);
        return TransactionalOperator.create(txManager, definition);
    }

    /**
     * R2DBC audit adapter for the operational config plane.
     *
     * <p>Wired with the {@code auditTransactionalOperator} ({@code REQUIRES_NEW}) so that
     * audit events are committed independently of the outer writer transaction (AD-S4).
     *
     * @param databaseClient             the auto-configured, tenant-aware client
     * @param auditTransactionalOperator the {@code REQUIRES_NEW} operator (qualified)
     * @param objectMapper               the auto-configured Jackson mapper for JSONB serialization
     * @return the adapter exposing {@link com.eudistack.ebw.wallet.config.domain.port.OperationalConfigAuditPort}
     */
    @Bean
    public OperationalConfigAuditR2dbcAdapter operationalConfigAuditR2dbcAdapter(
            DatabaseClient databaseClient,
            @Qualifier("auditTransactionalOperator") TransactionalOperator auditTransactionalOperator,
            ObjectMapper objectMapper) {
        return new OperationalConfigAuditR2dbcAdapter(databaseClient, auditTransactionalOperator, objectMapper);
    }

    /**
     * AWS KMS envelope encryption adapter.
     *
     * <p>The probe timeout is read from {@code wallet-ebw.probe.timeout-ms} (default 5000 ms)
     * and converted to a {@link Duration} for the adapter constructor.
     *
     * @param kmsAsyncClient  the AWS SDK v2 async KMS client (from {@link
     *                        com.eudistack.ebw.wallet.config.infrastructure.adapter.kms.KmsClientConfig})
     * @param probeTimeoutMs  the KMS call timeout in milliseconds
     * @return the adapter exposing {@link com.eudistack.ebw.wallet.config.domain.port.EnvelopeEncryptionPort}
     */
    @Bean
    public KmsEnvelopeEncryptionAdapter kmsEnvelopeEncryptionAdapter(
            KmsAsyncClient kmsAsyncClient,
            @Value("${wallet-ebw.probe.timeout-ms:5000}") long probeTimeoutMs) {
        return new KmsEnvelopeEncryptionAdapter(kmsAsyncClient, Duration.ofMillis(probeTimeoutMs));
    }

    /**
     * DB-TDE connectivity probe adapter.
     *
     * <p>Performs two sequential checks: KMS CMK accessibility ({@code kms:DescribeKey})
     * and sub-table accessibility ({@code wallet_operational_config_db_tde}) wrapped in a
     * Micrometer observation span (E-5).
     *
     * @param kmsEnvelopeEncryptionAdapter  the KMS port (from this configuration class)
     * @param operationalConfigR2dbcAdapter the operational config port (from this configuration class)
     * @param observationRegistry           the Micrometer registry for OTEL spans
     * @return the probe adapter for {@link KeyManager#DB_TDE}
     */
    @Bean
    public DbTdeProbeAdapter dbTdeProbeAdapter(
            KmsEnvelopeEncryptionAdapter kmsEnvelopeEncryptionAdapter,
            OperationalConfigR2dbcAdapter operationalConfigR2dbcAdapter,
            ObservationRegistry observationRegistry) {
        return new DbTdeProbeAdapter(
                kmsEnvelopeEncryptionAdapter, operationalConfigR2dbcAdapter, observationRegistry);
    }

    /**
     * Registry that dispatches probe calls to the appropriate {@link
     * com.eudistack.ebw.wallet.config.infrastructure.adapter.probe.ProbeAdapter} by
     * {@link KeyManager}.
     *
     * <p>In MVP (US-03), the registry contains exactly one entry:
     * {@link KeyManager#DB_TDE} → {@link DbTdeProbeAdapter}. Future Stories add entries here.
     *
     * @param dbTdeProbeAdapter the probe adapter for DB_TDE (from this configuration class)
     * @return the registry exposing {@link com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort}
     */
    @Bean
    public KeyManagerProbeRegistry keyManagerProbeRegistry(DbTdeProbeAdapter dbTdeProbeAdapter) {
        return new KeyManagerProbeRegistry(Map.of(KeyManager.DB_TDE, dbTdeProbeAdapter));
    }
}
