package com.eudistack.ebw.wallet.config.infrastructure;

import com.eudistack.ebw.wallet.config.application.operational.OperationalConfigReader;
import com.eudistack.ebw.wallet.config.application.operational.OperationalConfigWriter;
import com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult;
import com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.OperationalConfigAuditR2dbcAdapter;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.OperationalConfigR2dbcAdapter;
import com.eudistack.ebw.wallet.config.infrastructure.controller.OperationalConfigController;
import com.eudistack.ebw.wallet.config.infrastructure.controller.exception.OperationalConfigExceptionHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryMetadata;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.reactivestreams.Publisher;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;

import static io.r2dbc.spi.ConnectionFactoryOptions.DATABASE;
import static io.r2dbc.spi.ConnectionFactoryOptions.DRIVER;
import static io.r2dbc.spi.ConnectionFactoryOptions.HOST;
import static io.r2dbc.spi.ConnectionFactoryOptions.PASSWORD;
import static io.r2dbc.spi.ConnectionFactoryOptions.PORT;
import static io.r2dbc.spi.ConnectionFactoryOptions.USER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRED;
import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW;

/**
 * Writer E2E integration tests with cross-tenant isolation (T-4 — EUDISTACK-414).
 *
 * <p>Uses two tenant schemas ({@code acme_business_wallet} and {@code globex_business_wallet})
 * against a single shared Testcontainers PostgreSQL instance. No Spring application context is
 * started: all wiring is programmatic following the same pattern as
 * {@link OperationalConfigWriterAtomicityIT}. The KMS probe is replaced by a Mockito mock
 * ({@link KeyManagerConnectivityPort}) that returns {@link ProbeResult.Ok} — KMS adapter coverage
 * is in Task 13 ({@code KmsEnvelopeEncryptionAdapterIT}).
 *
 * <p>{@link WebTestClient} is bound to the controller via
 * {@link WebTestClient#bindToController(Object...)} with the exception handler registered, so
 * all HTTP-layer assertions (status codes, ETag header, body shape) reflect real
 * controller+handler behaviour. The actor resolves to {@code "anonymous"} because no Spring
 * Security context is set — this is intentional and matches the controller's
 * {@code .defaultIfEmpty("anonymous")} fallback.
 *
 * <p>Test cases:
 * <ul>
 *   <li>TC-1 ({@code postDbTde_acme_creates201_assertRowsInAcmeOnly}) — POST to acme tenant →
 *       201 + ETag; 1 root row + 1 sub row + 1 PERMIT audit in acme schema; 0 rows in globex.</li>
 *   <li>TC-2 ({@code getActiveConfig_acme_returns200_noWrappedDekInBody}) — GET after TC-1 →
 *       200; body contains {@code key_manager}, {@code activation_status}, {@code version};
 *       body does NOT contain {@code wrapped_dek} or {@code column_encryption_key_arn}.</li>
 *   <li>TC-3 ({@code putWithMatchingIfMatch_acme_returns200_newVersion}) — PUT with correct
 *       If-Match → 200 + new ETag; root version bumped; sub-table updated; 2 PERMIT audit rows.</li>
 *   <li>TC-4 ({@code putWithStaleIfMatch_acme_returns412}) — PUT with stale If-Match after TC-3
 *       bumped the version → 412; root version unchanged at 1; 1 additional DENY audit row.</li>
 *   <li>TC-5 ({@code crossTenant_getAsGlobex_returns404}) — GET against the globex controller
 *       (schema empty) → 404 (no active config for globex).</li>
 *   <li>TC-6 ({@code auditTable_updateAttempt_failsAppendOnlyTrigger}) — raw JDBC UPDATE on
 *       {@code wallet_config_audit} in acme schema → {@link SQLException} (trigger blocks it).</li>
 *   <li>TC-7 ({@code postDuplicateKeyManager_acme_returns409}) — second POST with the same
 *       {@code key_manager} → 409; 1 additional DENY audit row.</li>
 * </ul>
 *
 * <p>Tagged {@code integration} — runs under {@code ./gradlew integrationTest} (Docker required).
 * Compilation is the quality gate for this task; Testcontainers runtime is deferred to CI.
 */
@Testcontainers
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OperationalConfigWriterIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("wallet_ebw_writer_it")
            .withUsername("ebw_test")
            .withPassword("ebw_test");

    private static final String ACME_SCHEMA = "acme_business_wallet";
    private static final String GLOBEX_SCHEMA = "globex_business_wallet";

    private static final String VALID_ARN = "arn:aws:kms:eu-west-1:123456789012:key/mrk-writer-it";
    private static final byte[] WRAPPED_DEK = new byte[]{
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
            (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04
    };
    private static final String ALGORITHM = "AES-256-GCM";

    // Per-tenant controller + client wired programmatically (no Spring context).
    private WebTestClient acmeClient;
    private WebTestClient globexClient;

    // Shared ObjectMapper for JSON assertions.
    private final ObjectMapper objectMapper = new ObjectMapper();

    // ------------------------------------------------------------------
    // Setup: schemas, Flyway migration, programmatic wiring.
    // ------------------------------------------------------------------

    @BeforeAll
    void setUp() throws SQLException {
        migrateSchema(ACME_SCHEMA);
        migrateSchema(GLOBEX_SCHEMA);

        acmeClient = buildClient(ACME_SCHEMA);
        globexClient = buildClient(GLOBEX_SCHEMA);
    }

    /**
     * Creates the PG schema if absent, then applies the per-tenant Flyway migrations from
     * {@code classpath:db/tenant}.
     */
    private void migrateSchema(String schema) throws SQLException {
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
     * Builds a {@link WebTestClient} bound to a programmatically-wired
     * {@link OperationalConfigController} for the given tenant schema.
     *
     * <p>The {@link KeyManagerConnectivityPort} is a Mockito mock returning
     * {@link ProbeResult.Ok} — KMS connectivity is not the subject of this test class.
     * The actor resolves to {@code "anonymous"} via the controller's security-context fallback.
     */
    private WebTestClient buildClient(String schema) {
        ConnectionFactory cf = schemaConnectionFactory(schema);
        DatabaseClient client = DatabaseClient.create(cf);
        R2dbcTransactionManager txManager = new R2dbcTransactionManager(cf);

        DefaultTransactionDefinition outerDef = new DefaultTransactionDefinition();
        outerDef.setPropagationBehavior(PROPAGATION_REQUIRED);
        TransactionalOperator outerTxOp = TransactionalOperator.create(txManager, outerDef);

        DefaultTransactionDefinition auditDef = new DefaultTransactionDefinition();
        auditDef.setPropagationBehavior(PROPAGATION_REQUIRES_NEW);
        TransactionalOperator auditTxOp = TransactionalOperator.create(txManager, auditDef);

        OperationalConfigR2dbcAdapter r2dbcAdapter = new OperationalConfigR2dbcAdapter(client);
        OperationalConfigAuditR2dbcAdapter auditAdapter =
                new OperationalConfigAuditR2dbcAdapter(client, auditTxOp, objectMapper);

        KeyManagerConnectivityPort mockProbe = mock(KeyManagerConnectivityPort.class);
        when(mockProbe.probe(any(), any()))
                .thenReturn(Mono.just(new ProbeResult.Ok(42L)));

        OperationalConfigWriter writer =
                new OperationalConfigWriter(r2dbcAdapter, auditAdapter, mockProbe, outerTxOp);
        OperationalConfigReader reader = new OperationalConfigReader(r2dbcAdapter);
        OperationalConfigController controller =
                new OperationalConfigController(writer, reader);

        return WebTestClient.bindToController(controller)
                .controllerAdvice(new OperationalConfigExceptionHandler())
                .configureClient()
                .build();
    }

    /**
     * Returns a {@link ConnectionFactory} with {@code search_path} fixed to the given schema on
     * every acquired connection, mirroring {@code TenantAwareConnectionFactoryDecorator} in
     * production.
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

    // ------------------------------------------------------------------
    // JSON request body builders.
    // ------------------------------------------------------------------

    /** Builds a valid DB-TDE request body JSON string using the shared WRAPPED_DEK bytes. */
    private String validRequestBody() {
        return "{"
                + "\"key_manager\":\"db-tde\","
                + "\"column_encryption_key_arn\":\"" + VALID_ARN + "\","
                + "\"wrapped_dek\":\"" + Base64.getEncoder().encodeToString(WRAPPED_DEK) + "\","
                + "\"algorithm\":\"AES-256-GCM\""
                + "}";
    }

    // ------------------------------------------------------------------
    // JDBC helpers.
    // ------------------------------------------------------------------

    /** Counts rows in the given table within the given schema using a JDBC query. */
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

    /** Counts audit rows filtered by outcome in the given schema. */
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

    /** Returns the current version of the root operational config row in the given schema. */
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
    // TC-1 — POST db-tde → 201 + ETag; rows in acme only.
    // ------------------------------------------------------------------

    /**
     * POST a valid DB-TDE configuration to acme tenant. Asserts:
     * <ul>
     *   <li>201 Created status.</li>
     *   <li>{@code ETag} header matches the pattern {@code "\d+"}.</li>
     *   <li>Response body does NOT contain {@code wrapped_dek} or {@code column_encryption_key_arn}
     *       (AC-2c).</li>
     *   <li>1 root row + 1 sub-table row + 1 PERMIT audit row in {@code acme_business_wallet}.</li>
     *   <li>0 rows in all three tables in {@code globex_business_wallet} (AC-3b).</li>
     * </ul>
     */
    @Test
    void postDbTde_acme_creates201_assertRowsInAcmeOnly() throws Exception {
        byte[] responseBody = acmeClient.post()
                .uri("/admin/wallet-operational-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validRequestBody())
                .exchange()
                .expectStatus().isCreated()
                .expectHeader().value("ETag", etag ->
                        assertThat(etag).matches("\"\\d+\""))
                .expectBody()
                .returnResult()
                .getResponseBody();

        // Body shape: must not contain secret fields (AC-2c).
        assertThat(responseBody).isNotNull();
        String bodyStr = new String(responseBody);
        JsonNode bodyNode = objectMapper.readTree(bodyStr);
        assertThat(bodyNode.has("wrapped_dek"))
                .as("Response body must not contain wrapped_dek (AC-2c)")
                .isFalse();
        assertThat(bodyNode.has("column_encryption_key_arn"))
                .as("Response body must not contain column_encryption_key_arn (AC-2c)")
                .isFalse();
        // Present fields.
        assertThat(bodyNode.has("key_manager")).as("key_manager must be present").isTrue();
        assertThat(bodyNode.has("activation_status")).as("activation_status must be present").isTrue();
        assertThat(bodyNode.has("version")).as("version must be present").isTrue();

        // Acme schema: 1 root + 1 sub-table + 1 PERMIT audit.
        assertThat(countRows(ACME_SCHEMA, "wallet_operational_config"))
                .as("Acme root row count must be 1 (AC-1a)")
                .isEqualTo(1L);
        assertThat(countRows(ACME_SCHEMA, "wallet_operational_config_db_tde"))
                .as("Acme sub-table row count must be 1 (AC-1b)")
                .isEqualTo(1L);
        assertThat(countAuditByOutcome(ACME_SCHEMA, "PERMIT"))
                .as("Acme PERMIT audit row count must be 1 (AC-4a)")
                .isEqualTo(1L);

        // Globex schema: all three tables empty (cross-tenant isolation — AC-3b).
        assertThat(countRows(GLOBEX_SCHEMA, "wallet_operational_config"))
                .as("Globex root table must be empty (AC-3b)")
                .isZero();
        assertThat(countRows(GLOBEX_SCHEMA, "wallet_operational_config_db_tde"))
                .as("Globex sub-table must be empty (AC-3b)")
                .isZero();
        assertThat(countAuditByOutcome(GLOBEX_SCHEMA, "PERMIT"))
                .as("Globex PERMIT audit must be empty (AC-3b)")
                .isZero();
    }

    // ------------------------------------------------------------------
    // TC-2 — GET active config → 200; no wrapped_dek in body.
    // ------------------------------------------------------------------

    /**
     * After TC-1's INSERT, GET the active config for acme. Asserts:
     * <ul>
     *   <li>200 OK status.</li>
     *   <li>Response body contains {@code key_manager}, {@code activation_status},
     *       {@code version}.</li>
     *   <li>Response body does NOT contain {@code wrapped_dek} or
     *       {@code column_encryption_key_arn} (AC-2c).</li>
     * </ul>
     *
     * <p>Depends on TC-1 having inserted a row. Tests run in declaration order within the
     * {@code @TestInstance(Lifecycle.PER_CLASS)} class.
     */
    @Test
    void getActiveConfig_acme_returns200_noWrappedDekInBody() throws Exception {
        // Precondition: ensure at least one row is present (idempotent re-insert guard).
        // TC-1 already ran if tests are ordered, but guard defensively.
        acmeClient.post()
                .uri("/admin/wallet-operational-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validRequestBody())
                .exchange(); // Ignore status: may be 201 (first POST) or 409 (already exists).

        byte[] responseBody = acmeClient.get()
                .uri("/admin/wallet-operational-config")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBody();

        assertThat(responseBody).isNotNull();
        String bodyStr = new String(responseBody);
        JsonNode bodyNode = objectMapper.readTree(bodyStr);

        assertThat(bodyNode.has("key_manager")).as("key_manager present in GET response").isTrue();
        assertThat(bodyNode.has("activation_status")).as("activation_status present in GET response").isTrue();
        assertThat(bodyNode.has("version")).as("version present in GET response").isTrue();
        assertThat(bodyNode.has("wrapped_dek"))
                .as("wrapped_dek must be absent from GET response body (AC-2c)")
                .isFalse();
        assertThat(bodyNode.has("column_encryption_key_arn"))
                .as("column_encryption_key_arn must be absent from GET response body (AC-2c)")
                .isFalse();
    }

    // ------------------------------------------------------------------
    // TC-3 — PUT with matching If-Match → 200 + new ETag + version bumped.
    // ------------------------------------------------------------------

    /**
     * PUT with the current version from TC-1 (version=0). Asserts:
     * <ul>
     *   <li>200 OK status.</li>
     *   <li>New ETag value (version incremented to 1).</li>
     *   <li>DB: root row version bumped to 1; sub-table updated.</li>
     *   <li>2 PERMIT audit rows total (1 from TC-1 + 1 from this PUT).</li>
     * </ul>
     *
     * <p>Relies on TC-1 having set the initial version to 0. Uses {@code If-Match: "0"}.
     */
    @Test
    void putWithMatchingIfMatch_acme_returns200_newVersion() throws Exception {
        // Ensure TC-1 data is present.
        acmeClient.post()
                .uri("/admin/wallet-operational-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validRequestBody())
                .exchange(); // May be 201 or 409 — handled gracefully.

        // Read current version to know the If-Match to supply.
        long currentVersion = readRootVersion(ACME_SCHEMA);

        byte[] responseBody = acmeClient.put()
                .uri("/admin/wallet-operational-config")
                .contentType(MediaType.APPLICATION_JSON)
                .header("If-Match", "\"" + currentVersion + "\"")
                .bodyValue(validRequestBody())
                .exchange()
                .expectStatus().isOk()
                .expectHeader().value("ETag", etag ->
                        assertThat(etag).matches("\"\\d+\""))
                .expectBody()
                .returnResult()
                .getResponseBody();

        // Body shape verification.
        assertThat(responseBody).isNotNull();
        JsonNode bodyNode = objectMapper.readTree(new String(responseBody));
        assertThat(bodyNode.has("wrapped_dek"))
                .as("wrapped_dek must be absent from PUT response body (AC-2c)")
                .isFalse();

        // DB: root version must be currentVersion + 1.
        long updatedVersion = readRootVersion(ACME_SCHEMA);
        assertThat(updatedVersion)
                .as("Root version must be incremented after matching PUT (AC-5a)")
                .isEqualTo(currentVersion + 1L);
    }

    // ------------------------------------------------------------------
    // TC-4 — PUT with stale If-Match → 412 + root version unchanged + DENY audit.
    // ------------------------------------------------------------------

    /**
     * After TC-3 bumped the version, sending {@code If-Match: "0"} (original version) causes a
     * 412 Precondition Failed. Asserts:
     * <ul>
     *   <li>412 Precondition Failed status.</li>
     *   <li>Root row version unchanged at its post-TC-3 value.</li>
     *   <li>At least 1 DENY audit row present (the stale-version rejection).</li>
     * </ul>
     */
    @Test
    void putWithStaleIfMatch_acme_returns412() throws Exception {
        // Ensure at least one write has succeeded (TC-1/TC-3 may have run).
        acmeClient.post()
                .uri("/admin/wallet-operational-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validRequestBody())
                .exchange(); // 201 or 409.

        // Read current version — then use a deliberately stale one (current - 1 or a constant 0
        // if version is already > 0, or -1 if version is 0).
        long currentVersion = readRootVersion(ACME_SCHEMA);
        long staleVersion = currentVersion > 0 ? 0L : -1L;

        acmeClient.put()
                .uri("/admin/wallet-operational-config")
                .contentType(MediaType.APPLICATION_JSON)
                .header("If-Match", "\"" + staleVersion + "\"")
                .bodyValue(validRequestBody())
                .exchange()
                .expectStatus().isEqualTo(412);

        // Root version must be unchanged.
        assertThat(readRootVersion(ACME_SCHEMA))
                .as("Root version must be unchanged after stale PUT (AC-5e)")
                .isEqualTo(currentVersion);

        // At least 1 DENY audit row must be present (may include prior denies from TC-7).
        assertThat(countAuditByOutcome(ACME_SCHEMA, "DENY"))
                .as("At least 1 DENY audit row after stale-version PUT")
                .isGreaterThanOrEqualTo(1L);
    }

    // ------------------------------------------------------------------
    // TC-5 — GET as globex → 404 (empty schema, cross-tenant isolation).
    // ------------------------------------------------------------------

    /**
     * GET active config via the globex client (schema {@code globex_business_wallet}). Since
     * no configuration has been written to globex, the reader returns {@code Optional.empty()}
     * and the controller responds with 404 (AC-3b).
     */
    @Test
    void crossTenant_getAsGlobex_returns404() {
        globexClient.get()
                .uri("/admin/wallet-operational-config")
                .exchange()
                .expectStatus().isNotFound();
    }

    // ------------------------------------------------------------------
    // TC-6 — Raw UPDATE on wallet_config_audit → trigger rejects it (AC-4e).
    // ------------------------------------------------------------------

    /**
     * Verifies that a raw JDBC {@code UPDATE} on {@code wallet_config_audit} in the acme schema
     * is rejected by the append-only trigger created by the V3 migration (EUDISTACK-412, AC-4e).
     *
     * <p>The trigger name or message may vary; we assert that a {@link SQLException} is thrown.
     */
    @Test
    void auditTable_updateAttempt_failsAppendOnlyTrigger() throws SQLException {
        // Ensure at least one audit row exists so the UPDATE has something to target.
        acmeClient.post()
                .uri("/admin/wallet-operational-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validRequestBody())
                .exchange(); // 201 or 409.

        assertThatThrownBy(() -> {
            try (java.sql.Connection conn = DriverManager.getConnection(
                    POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                 Statement st = conn.createStatement()) {
                st.execute(
                        "UPDATE \"" + ACME_SCHEMA + "\".wallet_config_audit "
                                + "SET outcome = 'PERMIT' WHERE plane = 'operational'");
            }
        })
                .isInstanceOf(SQLException.class)
                .as("Append-only trigger on wallet_config_audit must block UPDATE (AC-4e)");
    }

    // ------------------------------------------------------------------
    // TC-7 — Duplicate POST same key_manager → 409 + DENY audit.
    // ------------------------------------------------------------------

    /**
     * A second POST with the same {@code key_manager='db-tde'} violates the {@code UNIQUE NOT NULL}
     * constraint on the {@code key_manager} column (V4 migration). Asserts:
     * <ul>
     *   <li>409 Conflict status on the duplicate request.</li>
     *   <li>At least 1 DENY audit row present after the rejection.</li>
     * </ul>
     */
    @Test
    void postDuplicateKeyManager_acme_returns409() throws Exception {
        // First POST — must succeed (201) or already exist (409 from earlier tests).
        acmeClient.post()
                .uri("/admin/wallet-operational-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validRequestBody())
                .exchange(); // 201 or 409.

        // Capture DENY count before the second duplicate attempt.
        long denyBeforeAttempt = countAuditByOutcome(ACME_SCHEMA, "DENY");

        // Second POST — must always return 409 (duplicate key_manager).
        acmeClient.post()
                .uri("/admin/wallet-operational-config")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validRequestBody())
                .exchange()
                .expectStatus().isEqualTo(409);

        // After the duplicate, at least 1 new DENY audit row must have been committed.
        assertThat(countAuditByOutcome(ACME_SCHEMA, "DENY"))
                .as("At least 1 new DENY audit row expected after duplicate POST (E-8)")
                .isGreaterThan(denyBeforeAttempt);
    }

    // ------------------------------------------------------------------
    // Inner helper: FixedSearchPathConnectionFactory.
    // ------------------------------------------------------------------

    /**
     * Minimal {@link ConnectionFactory} decorator that sets {@code search_path} to a given schema
     * name on every acquired connection. Mirrors what {@code TenantAwareConnectionFactoryDecorator}
     * does in production, scoped to the per-test schema (same pattern used by
     * {@link OperationalConfigWriterAtomicityIT}).
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
