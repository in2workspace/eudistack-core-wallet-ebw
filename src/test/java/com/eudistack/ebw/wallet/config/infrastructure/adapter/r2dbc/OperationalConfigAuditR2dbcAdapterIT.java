package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalAuditEvent;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalAuditEvent.EventType;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalAuditEvent.FieldChange;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalAuditEvent.Outcome;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryMetadata;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static io.r2dbc.spi.ConnectionFactoryOptions.DATABASE;
import static io.r2dbc.spi.ConnectionFactoryOptions.DRIVER;
import static io.r2dbc.spi.ConnectionFactoryOptions.HOST;
import static io.r2dbc.spi.ConnectionFactoryOptions.PASSWORD;
import static io.r2dbc.spi.ConnectionFactoryOptions.PORT;
import static io.r2dbc.spi.ConnectionFactoryOptions.USER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRED;
import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW;

/**
 * Integration tests for {@link OperationalConfigAuditR2dbcAdapter} (T-AC4 — EUDISTACK-414).
 *
 * <p>Pure programmatic R2DBC + Testcontainers PG + Flyway. No Spring context. One isolated
 * schema per test method prevents cross-test pollution (same pattern as
 * {@code OperationalConfigSchemaMigrationIT}).
 *
 * <p>Test cases:
 * <ul>
 *   <li>TC-1: {@code recordPermit} inserts one row with {@code plane='operational'},
 *       {@code outcome='PERMIT'}.</li>
 *   <li>TC-2: {@code recordDeny} inserts one row with {@code outcome='DENY'} and the reason
 *       persisted.</li>
 *   <li>TC-3: {@code PROPAGATION_REQUIRES_NEW} — a {@code DENY} audit row survives an outer
 *       transaction rollback (AD-S4, AC-4c).</li>
 *   <li>TC-4: byte-array tripwire — a {@link FieldChange} with a {@code [B@<hex>} value causes
 *       {@link IllegalStateException} and no row is written (AC-4d).</li>
 * </ul>
 *
 * <p>Tagged {@code integration} — runs under {@code ./gradlew integrationTest} (Docker required).
 */
@Testcontainers
@Tag("integration")
class OperationalConfigAuditR2dbcAdapterIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("wallet_ebw_audit_it")
            .withUsername("ebw_test")
            .withPassword("ebw_test");

    // ------------------------------------------------------------------
    // Infrastructure helpers
    // ------------------------------------------------------------------

    /**
     * Returns a {@link ConnectionFactory} whose every connection has {@code search_path} fixed to
     * the given schema, so all queries run within that schema without table-name qualification.
     */
    private ConnectionFactory schemaConnectionFactory(String schema) {
        ConnectionFactory base = ConnectionFactories.get(ConnectionFactoryOptions.builder()
                .option(DRIVER, "postgresql")
                .option(HOST, POSTGRES.getHost())
                .option(PORT, POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT))
                .option(DATABASE, POSTGRES.getDatabaseName())
                .option(USER, POSTGRES.getUsername())
                .option(PASSWORD, POSTGRES.getPassword())
                .build());
        return new FixedSearchPathConnectionFactory(base, schema);
    }

    /**
     * Creates the PG schema if absent, then applies the per-tenant Flyway migrations from
     * {@code classpath:db/tenant} scoped to that schema.
     */
    private void migrate(String schema) throws SQLException {
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            st.execute("CREATE SCHEMA IF NOT EXISTS \"" + schema + "\"");
        }
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .schemas(schema)
                .locations("classpath:db/tenant")
                .load()
                .migrate();
    }

    /**
     * Returns a schema name safe for PG identifiers (max 63 chars), prefixed with {@code ait_}
     * (audit integration test).
     */
    private static String schema(String methodName) {
        String raw = "ait_" + methodName.toLowerCase().replaceAll("[^a-z0-9]", "_");
        return raw.length() > 63 ? raw.substring(0, 63) : raw;
    }

    /**
     * Constructs the adapter under test with a {@link ConnectionFactory} scoped to the given
     * schema. The {@code auditTransactionalOperator} propagation is controlled by the caller
     * (TC-3 verifies behaviour when {@code REQUIRES_NEW} is in effect).
     */
    private OperationalConfigAuditR2dbcAdapter buildAdapter(
            String schema, int propagation) {
        ConnectionFactory cf = schemaConnectionFactory(schema);
        DatabaseClient client = DatabaseClient.create(cf);
        R2dbcTransactionManager txManager = new R2dbcTransactionManager(cf);
        DefaultTransactionDefinition def = new DefaultTransactionDefinition();
        def.setPropagationBehavior(propagation);
        TransactionalOperator auditOp = TransactionalOperator.create(txManager, def);
        return new OperationalConfigAuditR2dbcAdapter(client, auditOp, new ObjectMapper());
    }

    /** Counts rows in {@code wallet_config_audit} for the given schema using JDBC. */
    private long countAuditRows(String schema) throws SQLException {
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(
                    "SELECT count(*) FROM \"" + schema + "\".wallet_config_audit");
            rs.next();
            return rs.getLong(1);
        }
    }

    /**
     * Reads one audit row from the given schema and returns {@code [plane, outcome, reason]}.
     * Caller must ensure exactly one row exists.
     */
    private String[] readAuditRow(String schema) throws SQLException {
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(
                    "SELECT plane, outcome, reason FROM \"" + schema + "\".wallet_config_audit LIMIT 1");
            rs.next();
            return new String[]{rs.getString("plane"), rs.getString("outcome"), rs.getString("reason")};
        }
    }

    /** Builds a minimal valid {@link OperationalAuditEvent} with the given outcome and reason. */
    private static OperationalAuditEvent buildEvent(Outcome outcome, Optional<String> reason) {
        return new OperationalAuditEvent(
                "it-test-actor",
                EventType.CONFIG_APPLIED,
                OperationalAuditEvent.OPERATIONAL_PLANE,
                outcome,
                List.of(OperationalAuditEvent.withPlaintextField("key_manager", null, "db-tde", true)),
                reason,
                UUID.randomUUID().toString(),
                Instant.now()
        );
    }

    // ------------------------------------------------------------------
    // TC-1 — recordPermit inserts one row with plane='operational' and outcome='PERMIT'.
    // ------------------------------------------------------------------

    @Test
    void recordPermit_insertsRow_withPlaneOperational() throws SQLException {
        String schemaName = schema("recordPermit_insertsRow_withPlaneOperational");
        migrate(schemaName);

        OperationalConfigAuditR2dbcAdapter adapter = buildAdapter(schemaName, PROPAGATION_REQUIRES_NEW);
        OperationalAuditEvent event = buildEvent(Outcome.PERMIT, Optional.empty());

        StepVerifier.create(adapter.recordPermit(event))
                .verifyComplete();

        assertThat(countAuditRows(schemaName)).isEqualTo(1L);
        String[] row = readAuditRow(schemaName);
        assertThat(row[0]).as("plane").isEqualTo("operational");
        assertThat(row[1]).as("outcome").isEqualTo("PERMIT");
    }

    // ------------------------------------------------------------------
    // TC-2 — recordDeny inserts one row with outcome='DENY' and reason persisted.
    // ------------------------------------------------------------------

    @Test
    void recordDeny_insertsRow_withReason() throws SQLException {
        String schemaName = schema("recordDeny_insertsRow_withReason");
        migrate(schemaName);

        OperationalConfigAuditR2dbcAdapter adapter = buildAdapter(schemaName, PROPAGATION_REQUIRES_NEW);
        OperationalAuditEvent event = buildEvent(Outcome.DENY, Optional.of("probe: KMS unreachable"));

        StepVerifier.create(adapter.recordDeny(event))
                .verifyComplete();

        assertThat(countAuditRows(schemaName)).isEqualTo(1L);
        String[] row = readAuditRow(schemaName);
        assertThat(row[0]).as("plane").isEqualTo("operational");
        assertThat(row[1]).as("outcome").isEqualTo("DENY");
        assertThat(row[2]).as("reason").isEqualTo("probe: KMS unreachable");
    }

    // ------------------------------------------------------------------
    // TC-3 — REQUIRES_NEW: DENY audit row survives outer transaction rollback (AD-S4, AC-4c).
    //
    // The audit adapter is wired with REQUIRES_NEW. An outer TransactionalOperator with
    // REQUIRED wraps a call to recordDeny followed by Mono.error (forced rollback). After the
    // outer error the audit row must be present in the database because it was committed
    // independently in the REQUIRES_NEW sub-transaction.
    // ------------------------------------------------------------------

    @Test
    void requiresNew_auditSurvivesOuterTransactionRollback() throws SQLException {
        String schemaName = schema("requiresNew_auditSurvivesOuterTransactionRollback");
        migrate(schemaName);

        OperationalConfigAuditR2dbcAdapter auditAdapter =
                buildAdapter(schemaName, PROPAGATION_REQUIRES_NEW);

        // Outer TransactionalOperator (REQUIRED) — simulates the writer transaction.
        ConnectionFactory outerCf = schemaConnectionFactory(schemaName);
        R2dbcTransactionManager outerTxManager = new R2dbcTransactionManager(outerCf);
        DefaultTransactionDefinition outerDef = new DefaultTransactionDefinition();
        outerDef.setPropagationBehavior(PROPAGATION_REQUIRED);
        TransactionalOperator outerTxOp = TransactionalOperator.create(outerTxManager, outerDef);

        OperationalAuditEvent event = buildEvent(Outcome.DENY, Optional.of("forced rollback reason"));

        // Run inside the outer tx: audit then force rollback.
        Mono<Void> outerTx = outerTxOp.execute(tx ->
                auditAdapter.recordDeny(event)
                        .then(Mono.<Void>error(new RuntimeException("forced rollback")))
        ).then();

        StepVerifier.create(outerTx)
                .expectErrorMessage("forced rollback")
                .verify();

        // The DENY row must exist because the REQUIRES_NEW audit sub-transaction committed
        // independently before the outer tx rolled back (AD-S4 / AC-4c).
        assertThat(countAuditRows(schemaName))
                .as("DENY audit row must survive outer-tx rollback (AD-S4)")
                .isEqualTo(1L);
        String[] row = readAuditRow(schemaName);
        assertThat(row[1]).isEqualTo("DENY");
    }

    // ------------------------------------------------------------------
    // TC-4 — Byte-array tripwire: FieldChange with [B@<hex> value causes
    //         IllegalStateException and no row is written (AC-4d).
    // ------------------------------------------------------------------

    @Test
    void tripwire_unredactedByteArrayInFieldChange_throwsIllegalState() throws SQLException {
        String schemaName = schema("tripwire_unredactedByteArrayInFieldChange_throws");
        migrate(schemaName);

        OperationalConfigAuditR2dbcAdapter adapter = buildAdapter(schemaName, PROPAGATION_REQUIRES_NEW);

        // 'before' value matches the byte-array toString pattern [B@<hex>.
        FieldChange unredactedField = OperationalAuditEvent.withPlaintextField(
                "wrapped_dek", "[B@deadbeef", "<redacted>", true);

        OperationalAuditEvent event = new OperationalAuditEvent(
                "it-test-actor",
                EventType.CONFIG_APPLIED,
                OperationalAuditEvent.OPERATIONAL_PLANE,
                Outcome.PERMIT,
                List.of(unredactedField),
                Optional.empty(),
                UUID.randomUUID().toString(),
                Instant.now()
        );

        // The tripwire fires inside Mono.fromCallable and the error propagates as Mono.error.
        StepVerifier.create(adapter.recordPermit(event))
                .expectError(IllegalStateException.class)
                .verify();

        assertThat(countAuditRows(schemaName))
                .as("No row must be written when the byte-array tripwire fires (AC-4d)")
                .isZero();
    }

    // ------------------------------------------------------------------
    // Inner helper: connection factory that fixes search_path on every connection.
    // ------------------------------------------------------------------

    /**
     * Minimal {@link ConnectionFactory} decorator that sets {@code search_path} to a given schema
     * name on every acquired connection. Mirrors what {@code TenantAwareConnectionFactoryDecorator}
     * does in production, scoped to the per-test schema.
     */
    private static final class FixedSearchPathConnectionFactory implements ConnectionFactory {

        private final ConnectionFactory delegate;
        private final String schema;

        FixedSearchPathConnectionFactory(ConnectionFactory delegate, String schema) {
            this.delegate = delegate;
            this.schema = schema;
        }

        @Override
        public Publisher<? extends io.r2dbc.spi.Connection> create() {
            return Mono.from(delegate.create())
                    .flatMap(conn ->
                            Mono.from(conn.createStatement(
                                    "SET search_path TO \"" + schema + "\"").execute())
                                    .then(Mono.just(conn)));
        }

        @Override
        public ConnectionFactoryMetadata getMetadata() {
            return delegate.getMetadata();
        }
    }
}
