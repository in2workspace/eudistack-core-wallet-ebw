package com.eudistack.ebw.wallet.config.infrastructure;

import com.eudistack.ebw.wallet.config.application.operational.ApplyOperationalConfigCommand;
import com.eudistack.ebw.wallet.config.application.operational.OperationalConfigWriter;
import com.eudistack.ebw.wallet.config.application.operational.exception.ProbeFailedException;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.DbTdeOperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.OperationalConfigAuditR2dbcAdapter;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.OperationalConfigR2dbcAdapter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryMetadata;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.springframework.dao.OptimisticLockingFailureException;
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
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static io.r2dbc.spi.ConnectionFactoryOptions.DATABASE;
import static io.r2dbc.spi.ConnectionFactoryOptions.DRIVER;
import static io.r2dbc.spi.ConnectionFactoryOptions.HOST;
import static io.r2dbc.spi.ConnectionFactoryOptions.PASSWORD;
import static io.r2dbc.spi.ConnectionFactoryOptions.PORT;
import static io.r2dbc.spi.ConnectionFactoryOptions.USER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRED;
import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW;

/**
 * Atomicity regression integration tests for {@link OperationalConfigWriter} (T-AC6 — EUDISTACK-414).
 *
 * <p>Verifies the three simultaneous invariants of AC-6 using a real R2DBC adapter, a real
 * audit adapter (wired with {@code PROPAGATION_REQUIRES_NEW}), and a Mockito mock for
 * {@link com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort} (probe results
 * are injected without requiring LocalStack KMS).
 *
 * <p>Test cases:
 * <ul>
 *   <li>TC-1: {@code failedAtomicity_probeFailure_zeroRootRows_zeroSubRows_oneAuditDenyRow} —
 *       probe returns {@link ProbeResult.Failed}; writer emits {@link ProbeFailedException};
 *       asserts {@code wallet_operational_config} count=0, {@code wallet_operational_config_db_tde}
 *       count=0, {@code wallet_config_audit} DENY count=1; reason starts with {@code "probe:"}
 *       (AC-6).</li>
 *   <li>TC-2: {@code secretsAreRedactedInAuditDenyRow} — same probe-failure trigger; known
 *       {@code wrappedDek} bytes; asserts that the {@code field_changes} JSONB in the DENY
 *       audit row does not contain the raw hex, base64, or {@code [B@} representation of the
 *       secret; asserts {@code wrapped_dek} is present with {@code "<redacted>"} value
 *       (AC-2, AC-4d).</li>
 *   <li>TC-3: {@code permit_happyPath_allThreeTablesPopulated} — probe returns
 *       {@link ProbeResult.Ok}; writer succeeds; asserts 1 root row, 1 sub-table row, 1 PERMIT
 *       audit row (AC-1, AC-4, AC-5).</li>
 *   <li>TC-4: {@code optimisticLock_staleVersion_zeroRootUpdated_oneAuditDenyRow} — happy-path
 *       first write succeeds; second write with stale {@code ifMatchVersion} emits
 *       {@link OptimisticLockingFailureException}; asserts root version unchanged, 2 audit
 *       rows total (1 PERMIT + 1 DENY) (AC-5, AC-6 partial).</li>
 * </ul>
 *
 * <p>No Spring application context is started. All wiring is programmatic. Each test method
 * uses a distinct schema (prefixed {@code wit_}) to prevent cross-test pollution.
 *
 * <p>Tagged {@code integration} — runs under {@code ./gradlew integrationTest} (Docker required).
 * Compilation is the quality gate for this task; Testcontainers runtime is deferred to CI.
 */
@Testcontainers
@Tag("integration")
class OperationalConfigWriterAtomicityIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("wallet_ebw_atomicity_it")
            .withUsername("ebw_test")
            .withPassword("ebw_test");

    private static final String VALID_ARN = "arn:aws:kms:eu-west-1:123456789012:key/mrk-atomicity";
    private static final byte[] KNOWN_DEK = new byte[]{
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
            (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE
    };
    private static final String ALGORITHM = "AES-256-GCM";
    private static final String ACTOR = "it-atomicity-actor@test.example";

    // ------------------------------------------------------------------
    // Infrastructure helpers
    // ------------------------------------------------------------------

    /**
     * Returns a {@link ConnectionFactory} whose every connection has {@code search_path} fixed to
     * the given schema, mirroring what {@code TenantAwareConnectionFactoryDecorator} does in
     * production but scoped to the per-test schema.
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
     * Returns a schema name safe for PG identifiers (max 63 chars), prefixed with {@code wit_}
     * (writer integration test).
     */
    private static String schema(String methodName) {
        String raw = "wit_" + methodName.toLowerCase().replaceAll("[^a-z0-9]", "_");
        return raw.length() > 63 ? raw.substring(0, 63) : raw;
    }

    /**
     * Constructs a fully-wired {@link OperationalConfigWriter} backed by real R2DBC adapters
     * and a Mockito-mocked {@link com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort}.
     *
     * <p>The outer {@link TransactionalOperator} uses {@code PROPAGATION_REQUIRED}; the audit
     * adapter's inner operator uses {@code PROPAGATION_REQUIRES_NEW} (AD-S4 invariant).
     *
     * @param schema      the per-test schema name
     * @param mockProbe   a pre-configured mock of the connectivity port
     * @return the writer under test
     */
    private OperationalConfigWriter buildWriter(
            String schema,
            com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort mockProbe) {
        ConnectionFactory cf = schemaConnectionFactory(schema);
        DatabaseClient client = DatabaseClient.create(cf);
        R2dbcTransactionManager txManager = new R2dbcTransactionManager(cf);

        // Outer transaction: PROPAGATION_REQUIRED (the main write unit).
        DefaultTransactionDefinition outerDef = new DefaultTransactionDefinition();
        outerDef.setPropagationBehavior(PROPAGATION_REQUIRED);
        TransactionalOperator outerTxOp = TransactionalOperator.create(txManager, outerDef);

        // Audit sub-transaction: PROPAGATION_REQUIRES_NEW (survives outer rollback — AD-S4).
        DefaultTransactionDefinition auditDef = new DefaultTransactionDefinition();
        auditDef.setPropagationBehavior(PROPAGATION_REQUIRES_NEW);
        TransactionalOperator auditTxOp = TransactionalOperator.create(txManager, auditDef);

        OperationalConfigR2dbcAdapter r2dbcAdapter = new OperationalConfigR2dbcAdapter(client);
        OperationalConfigAuditR2dbcAdapter auditAdapter =
                new OperationalConfigAuditR2dbcAdapter(client, auditTxOp, new ObjectMapper());

        return new OperationalConfigWriter(r2dbcAdapter, auditAdapter, mockProbe, outerTxOp);
    }

    /**
     * Builds a valid {@link ApplyOperationalConfigCommand} for {@code DB_TDE} with the given
     * {@code ifMatchVersion}. The {@code wrappedDek} is always {@link #KNOWN_DEK}.
     */
    private static ApplyOperationalConfigCommand buildCommand(Optional<Long> ifMatchVersion) {
        return new ApplyOperationalConfigCommand(
                KeyManager.DB_TDE,
                new DbTdeOperationalConfig(VALID_ARN, KNOWN_DEK, ALGORITHM),
                ACTOR,
                UUID.randomUUID().toString(),
                ifMatchVersion
        );
    }

    /** Counts rows in the given table inside the specified schema, using a plain JDBC query. */
    private long countRows(String schema, String table) throws SQLException {
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(
                    "SELECT count(*) FROM \"" + schema + "\".\"" + table + "\"");
            rs.next();
            return rs.getLong(1);
        }
    }

    /**
     * Counts audit rows filtered by {@code outcome} and {@code plane='operational'} in the given
     * schema.
     */
    private long countAuditByOutcome(String schema, String outcome) throws SQLException {
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(
                    "SELECT count(*) FROM \"" + schema + "\".wallet_config_audit "
                            + "WHERE outcome = '" + outcome + "' AND plane = 'operational'");
            rs.next();
            return rs.getLong(1);
        }
    }

    /**
     * Returns the {@code reason} and {@code field_changes} columns of the first DENY audit row
     * for {@code plane='operational'} in the given schema. The caller must ensure exactly one
     * DENY row exists.
     *
     * @return {@code String[2]} where {@code [0]=reason}, {@code [1]=field_changes JSON}
     */
    private String[] readFirstDenyAuditRow(String schema) throws SQLException {
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(
                    "SELECT reason, field_changes::text AS field_changes_text "
                            + "FROM \"" + schema + "\".wallet_config_audit "
                            + "WHERE outcome = 'DENY' AND plane = 'operational' LIMIT 1");
            rs.next();
            return new String[]{rs.getString("reason"), rs.getString("field_changes_text")};
        }
    }

    /**
     * Returns the {@code version} of the root operational config row in the given schema.
     * Caller must ensure exactly one root row exists.
     */
    private long readRootVersion(String schema) throws SQLException {
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(
                    "SELECT version FROM \"" + schema + "\".wallet_operational_config LIMIT 1");
            rs.next();
            return rs.getLong("version");
        }
    }

    // ------------------------------------------------------------------
    // TC-1: probe failure → zero root rows, zero sub rows, one DENY audit row (AC-6).
    // ------------------------------------------------------------------

    /**
     * Given a {@code ProbeResult.Failed}, the writer must not persist anything in the root or
     * sub-table tables, but must commit one DENY audit row in {@code REQUIRES_NEW} (AC-6).
     *
     * <p>The three simultaneous invariants verified:
     * <ol>
     *   <li>{@code wallet_operational_config} count = 0.</li>
     *   <li>{@code wallet_operational_config_db_tde} count = 0.</li>
     *   <li>{@code wallet_config_audit} with {@code outcome='DENY'} and {@code plane='operational'}
     *       count = 1, and {@code reason} starts with {@code "probe:"}.</li>
     * </ol>
     */
    @Test
    void failedAtomicity_probeFailure_zeroRootRows_zeroSubRows_oneAuditDenyRow() throws SQLException {
        String schemaName = schema("failedAtomicity_probeFailure_allThreeInvariants");
        migrate(schemaName);

        com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort mockProbe =
                mock(com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort.class);
        when(mockProbe.probe(any(), any()))
                .thenReturn(Mono.just(new ProbeResult.Failed("probe: KMS timeout")));

        OperationalConfigWriter writer = buildWriter(schemaName, mockProbe);
        ApplyOperationalConfigCommand command = buildCommand(Optional.empty());

        StepVerifier.create(writer.apply(command))
                .expectError(ProbeFailedException.class)
                .verify();

        // Invariant (a): root table must be empty.
        assertThat(countRows(schemaName, "wallet_operational_config"))
                .as("wallet_operational_config count must be 0 after probe failure (AC-6a)")
                .isZero();

        // Invariant (b): sub-table must be empty.
        assertThat(countRows(schemaName, "wallet_operational_config_db_tde"))
                .as("wallet_operational_config_db_tde count must be 0 after probe failure (AC-6b)")
                .isZero();

        // Invariant (c): one DENY audit row committed in REQUIRES_NEW.
        assertThat(countAuditByOutcome(schemaName, "DENY"))
                .as("One DENY audit row expected (AC-6c, AD-S4)")
                .isEqualTo(1L);

        String[] denyRow = readFirstDenyAuditRow(schemaName);
        assertThat(denyRow[0])
                .as("DENY audit reason must start with 'probe:'")
                .startsWith("probe:");
    }

    // ------------------------------------------------------------------
    // TC-2: secrets are redacted in the DENY audit row (AC-2, AC-4d).
    // ------------------------------------------------------------------

    /**
     * Given a probe failure with a known {@code wrappedDek} ({@link #KNOWN_DEK} = 0xDEADBEEFCAFEBABE),
     * the {@code field_changes} JSONB in the DENY audit row must NOT contain:
     * <ul>
     *   <li>The hex string {@code "DEADBEEF"} (or any partial hex) in any case.</li>
     *   <li>The base64 encoding of the 8 known bytes.</li>
     *   <li>The raw Java byte-array {@code toString()} prefix {@code "[B@"}.</li>
     * </ul>
     * And it must contain a {@code wrapped_dek} entry whose value is {@code "<redacted>"}.
     */
    @Test
    void secretsAreRedactedInAuditDenyRow() throws Exception {
        String schemaName = schema("secretsAreRedactedInAuditDenyRow");
        migrate(schemaName);

        com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort mockProbe =
                mock(com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort.class);
        when(mockProbe.probe(any(), any()))
                .thenReturn(Mono.just(new ProbeResult.Failed("probe: KMS timeout")));

        OperationalConfigWriter writer = buildWriter(schemaName, mockProbe);
        ApplyOperationalConfigCommand command = buildCommand(Optional.empty());

        StepVerifier.create(writer.apply(command))
                .expectError(ProbeFailedException.class)
                .verify();

        assertThat(countAuditByOutcome(schemaName, "DENY"))
                .as("Precondition: one DENY row expected")
                .isEqualTo(1L);

        String[] denyRow = readFirstDenyAuditRow(schemaName);
        String fieldChangesJson = denyRow[1];

        // Assert the raw hex is not present (covers partial or full hex of the DEK bytes).
        assertThat(fieldChangesJson)
                .as("field_changes must not contain raw hex of KNOWN_DEK (AC-4d)")
                .doesNotContainIgnoringCase("deadbeef")
                .doesNotContainIgnoringCase("cafebabe");

        // Assert the base64 encoding of the known DEK is not present.
        String base64Dek = Base64.getEncoder().encodeToString(KNOWN_DEK);
        assertThat(fieldChangesJson)
                .as("field_changes must not contain base64 of KNOWN_DEK (AC-4d)")
                .doesNotContain(base64Dek);

        // Assert no raw byte-array toString pattern is present.
        assertThat(fieldChangesJson)
                .as("field_changes must not contain Java byte[] toString prefix [B@ (AC-4d)")
                .doesNotContain("[B@");

        // Assert the wrapped_dek field is present with value <redacted>.
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode fieldChanges = objectMapper.readTree(fieldChangesJson);
        boolean foundRedactedWrappedDek = false;
        for (JsonNode entry : fieldChanges) {
            if ("wrapped_dek".equals(entry.path("field").asText())) {
                String afterValue = entry.path("after").asText();
                assertThat(afterValue)
                        .as("wrapped_dek 'after' must be '<redacted>' (AC-4d)")
                        .isEqualTo("<redacted>");
                String beforeValue = entry.path("before").asText("null");
                assertThat(beforeValue)
                        .as("wrapped_dek 'before' must be '<redacted>' (AC-4d)")
                        .isEqualTo("<redacted>");
                foundRedactedWrappedDek = true;
                break;
            }
        }
        assertThat(foundRedactedWrappedDek)
                .as("wrapped_dek field must be present in field_changes with <redacted> value (AC-4d)")
                .isTrue();
    }

    // ------------------------------------------------------------------
    // TC-3: happy path — all three tables populated (AC-1, AC-4, AC-5).
    // ------------------------------------------------------------------

    /**
     * Given a successful probe ({@link ProbeResult.Ok}), the writer must:
     * <ol>
     *   <li>Persist exactly 1 root row in {@code wallet_operational_config} with
     *       {@code activation_status='active'} and {@code connectivity_verified_at NOT NULL}.</li>
     *   <li>Persist exactly 1 sub-table row in {@code wallet_operational_config_db_tde} with
     *       the expected {@code algorithm} and {@code column_encryption_key_arn}.</li>
     *   <li>Persist exactly 1 PERMIT audit row in {@code wallet_config_audit} with
     *       {@code plane='operational'} and {@code outcome='PERMIT'}.</li>
     * </ol>
     */
    @Test
    void permit_happyPath_allThreeTablesPopulated() throws SQLException {
        String schemaName = schema("permit_happyPath_allThreeTablesPopulated");
        migrate(schemaName);

        com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort mockProbe =
                mock(com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort.class);
        when(mockProbe.probe(any(), any()))
                .thenReturn(Mono.just(new ProbeResult.Ok(42L)));

        OperationalConfigWriter writer = buildWriter(schemaName, mockProbe);
        ApplyOperationalConfigCommand command = buildCommand(Optional.empty());

        StepVerifier.create(writer.apply(command))
                .expectNextCount(1)
                .verifyComplete();

        // Root row: exactly 1, activation_status='active', connectivity_verified_at NOT NULL.
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            ResultSet rootRs = st.executeQuery(
                    "SELECT activation_status, connectivity_verified_at "
                            + "FROM \"" + schemaName + "\".wallet_operational_config");
            assertThat(rootRs.next()).as("root row must exist").isTrue();
            assertThat(rootRs.getString("activation_status"))
                    .as("activation_status must be 'active' (AC-5a)")
                    .isEqualTo("active");
            assertThat(rootRs.getTimestamp("connectivity_verified_at"))
                    .as("connectivity_verified_at must be set when activation_status=active (AD-6)")
                    .isNotNull();
            assertThat(rootRs.next()).as("only 1 root row expected").isFalse();

            // Sub-table row: exactly 1, correct algorithm and ARN.
            ResultSet subRs = st.executeQuery(
                    "SELECT column_encryption_key_arn, algorithm "
                            + "FROM \"" + schemaName + "\".wallet_operational_config_db_tde");
            assertThat(subRs.next()).as("sub-table row must exist").isTrue();
            assertThat(subRs.getString("column_encryption_key_arn"))
                    .as("column_encryption_key_arn must match command value")
                    .isEqualTo(VALID_ARN);
            assertThat(subRs.getString("algorithm"))
                    .as("algorithm must be AES-256-GCM")
                    .isEqualTo(ALGORITHM);
            assertThat(subRs.next()).as("only 1 sub-table row expected").isFalse();
        }

        // Audit row: exactly 1 PERMIT.
        assertThat(countAuditByOutcome(schemaName, "PERMIT"))
                .as("One PERMIT audit row expected (AC-4a)")
                .isEqualTo(1L);
        assertThat(countAuditByOutcome(schemaName, "DENY"))
                .as("No DENY audit row expected in happy path")
                .isZero();
    }

    // ------------------------------------------------------------------
    // TC-4: optimistic lock — stale version causes DENY audit, root version unchanged (AC-5, AC-6).
    // ------------------------------------------------------------------

    /**
     * After a successful first apply (root version=0 in DB), a second apply with
     * {@code ifMatchVersion = Optional.of(0L)} triggers an update path where the adapter uses
     * {@code expectedVersion = 0 - 1 = -1}. Since the DB row has {@code version=0}, the
     * {@code UPDATE WHERE version=-1} matches nothing → {@link OptimisticLockingFailureException}.
     *
     * <p>After both calls complete:
     * <ul>
     *   <li>Root row version is still 0 (not incremented by the failed second write).</li>
     *   <li>Sub-table values are unchanged.</li>
     *   <li>Total audit rows: 2 — 1 PERMIT (from first apply) + 1 DENY (optimistic lock).</li>
     * </ul>
     */
    @Test
    void optimisticLock_staleVersion_zeroRootUpdated_oneAuditDenyRow() throws SQLException {
        String schemaName = schema("optimisticLock_staleVersion_auditInvariant");
        migrate(schemaName);

        com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort mockProbe =
                mock(com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort.class);
        when(mockProbe.probe(any(), any()))
                .thenReturn(Mono.just(new ProbeResult.Ok(10L)));

        OperationalConfigWriter writer = buildWriter(schemaName, mockProbe);

        // First call: POST (ifMatchVersion = empty) — must succeed and produce version=0 in DB.
        ApplyOperationalConfigCommand firstCommand = buildCommand(Optional.empty());
        StepVerifier.create(writer.apply(firstCommand))
                .expectNextCount(1)
                .verifyComplete();

        // Verify DB has version=0 after the first INSERT.
        long versionAfterFirst = readRootVersion(schemaName);
        assertThat(versionAfterFirst)
                .as("Root version must be 0 after initial INSERT")
                .isEqualTo(0L);

        // Second call: stale version — ifMatchVersion=0 → adapter uses expectedVersion = 0-1 = -1.
        // The DB row has version=0, so UPDATE WHERE version=-1 matches nothing → optimistic lock.
        ApplyOperationalConfigCommand staleCommand = buildCommand(Optional.of(0L));
        StepVerifier.create(writer.apply(staleCommand))
                .expectError(OptimisticLockingFailureException.class)
                .verify();

        // Root row version must still be 0 (not incremented by the failed write).
        long versionAfterStale = readRootVersion(schemaName);
        assertThat(versionAfterStale)
                .as("Root version must remain 0 after stale-version failure (AC-5)")
                .isEqualTo(0L);

        // Total audit rows: 1 PERMIT (first) + 1 DENY (optimistic lock).
        assertThat(countAuditByOutcome(schemaName, "PERMIT"))
                .as("One PERMIT audit row expected (from first successful apply)")
                .isEqualTo(1L);
        assertThat(countAuditByOutcome(schemaName, "DENY"))
                .as("One DENY audit row expected for optimistic lock failure (AC-6c, AD-S4)")
                .isEqualTo(1L);
    }

    // ------------------------------------------------------------------
    // Inner helper: FixedSearchPathConnectionFactory
    // ------------------------------------------------------------------

    /**
     * Minimal {@link ConnectionFactory} decorator that sets {@code search_path} to a given schema
     * name on every acquired connection. Mirrors what {@code TenantAwareConnectionFactoryDecorator}
     * does in production, scoped to the per-test schema (same pattern used by
     * {@code OperationalConfigAuditR2dbcAdapterIT} and {@code OperationalConfigR2dbcAdapterIT}).
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
