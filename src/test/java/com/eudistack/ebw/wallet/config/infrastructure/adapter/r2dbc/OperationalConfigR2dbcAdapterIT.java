package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.ActivationStatus;
import com.eudistack.ebw.wallet.config.domain.model.operational.DbTdeOperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfigDescriptor;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryMetadata;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.r2dbc.core.DatabaseClient;
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
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import static io.r2dbc.spi.ConnectionFactoryOptions.DATABASE;
import static io.r2dbc.spi.ConnectionFactoryOptions.DRIVER;
import static io.r2dbc.spi.ConnectionFactoryOptions.HOST;
import static io.r2dbc.spi.ConnectionFactoryOptions.PASSWORD;
import static io.r2dbc.spi.ConnectionFactoryOptions.PORT;
import static io.r2dbc.spi.ConnectionFactoryOptions.USER;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link OperationalConfigR2dbcAdapter} (T-AC1+AC5 — EUDISTACK-414).
 *
 * <p>Pure programmatic R2DBC + Testcontainers PG + Flyway. No Spring context. One isolated
 * schema per test method prevents cross-test pollution.
 *
 * <p>Test cases:
 * <ul>
 *   <li>TC-1: {@code findActive} on empty table returns {@link Optional#empty()}.</li>
 *   <li>TC-2: {@code upsert} insert path ({@code version=0}) creates both root and sub-table rows
 *       with correct values.</li>
 *   <li>TC-3: {@code upsert} update path ({@code version=existingVersion+1}) updates both rows;
 *       version is incremented in the DB.</li>
 *   <li>TC-4: {@code upsert} update path with stale version emits
 *       {@link OptimisticLockingFailureException}.</li>
 *   <li>TC-5: {@code canQuerySubtable(DB_TDE)} returns {@code true} after V4 migration.</li>
 *   <li>TC-6: {@code findActive} after an {@code is_active=true} insert returns a descriptor
 *       with all sub-table fields correctly populated (JOIN correctness).</li>
 * </ul>
 *
 * <p>Tagged {@code integration} — runs under {@code ./gradlew integrationTest} (Docker required).
 */
@Testcontainers
@Tag("integration")
class OperationalConfigR2dbcAdapterIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("wallet_ebw_r2dbc_it")
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
     * Returns a schema name safe for PG identifiers (max 63 chars), prefixed with {@code rit_}
     * (r2dbc integration test).
     */
    private static String schema(String methodName) {
        String raw = "rit_" + methodName.toLowerCase().replaceAll("[^a-z0-9]", "_");
        return raw.length() > 63 ? raw.substring(0, 63) : raw;
    }

    /** Constructs the adapter under test wired to the given schema's connection factory. */
    private OperationalConfigR2dbcAdapter buildAdapter(String schema) {
        return new OperationalConfigR2dbcAdapter(
                DatabaseClient.create(schemaConnectionFactory(schema)));
    }

    /**
     * Builds a valid {@link OperationalConfigDescriptor} for DB_TDE with the given
     * {@code version} and {@code activationStatus}. When {@code activationStatus=ACTIVE} a
     * non-null {@code connectivityVerifiedAt} is supplied; otherwise it is empty.
     */
    private static OperationalConfigDescriptor buildDescriptor(
            long version, ActivationStatus activationStatus) {
        Optional<Instant> cvAt = activationStatus == ActivationStatus.ACTIVE
                ? Optional.of(Instant.now())
                : Optional.empty();
        return new OperationalConfigDescriptor(
                UUID.randomUUID(),
                KeyManager.DB_TDE,
                new DbTdeOperationalConfig(
                        "arn:aws:kms:eu-west-1:123456789012:key/" + UUID.randomUUID(),
                        new byte[]{0x01, 0x02, 0x03, 0x04},
                        "AES-256-GCM"
                ),
                true,
                activationStatus,
                cvAt,
                version,
                "it-test-actor",
                Instant.now()
        );
    }

    // ------------------------------------------------------------------
    // TC-1 — findActive on empty table returns Optional.empty().
    // ------------------------------------------------------------------

    @Test
    void findActive_emptyTable_returnsEmptyOptional() throws SQLException {
        String schemaName = schema("findActive_emptyTable_returnsEmptyOptional");
        migrate(schemaName);

        OperationalConfigR2dbcAdapter adapter = buildAdapter(schemaName);

        StepVerifier.create(adapter.findActive())
                .assertNext(opt -> assertThat(opt).isEmpty())
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // TC-2 — upsert insert path (version=0) creates root and sub-table rows.
    // ------------------------------------------------------------------

    @Test
    void upsert_insertPath_createsRootAndSubRows() throws SQLException {
        String schemaName = schema("upsert_insertPath_createsRootAndSubRows");
        migrate(schemaName);

        OperationalConfigR2dbcAdapter adapter = buildAdapter(schemaName);
        OperationalConfigDescriptor descriptor = buildDescriptor(0L, ActivationStatus.ACTIVE);

        StepVerifier.create(adapter.upsert(descriptor))
                .assertNext(result -> assertThat(result.id()).isEqualTo(descriptor.id()))
                .verifyComplete();

        // Verify root row.
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            ResultSet rootRs = st.executeQuery(
                    "SELECT count(*) FROM \"" + schemaName + "\".wallet_operational_config");
            rootRs.next();
            assertThat(rootRs.getLong(1)).as("root row count").isEqualTo(1L);

            ResultSet subRs = st.executeQuery(
                    "SELECT count(*) FROM \"" + schemaName + "\".wallet_operational_config_db_tde");
            subRs.next();
            assertThat(subRs.getLong(1)).as("sub-table row count").isEqualTo(1L);
        }
    }

    // ------------------------------------------------------------------
    // TC-3 — upsert update path (version=existingVersion+1) updates both rows.
    //
    // The adapter's UPDATE path reads the existing id via SELECT ... WHERE is_active=true,
    // then issues UPDATE WHERE id=? AND version=expectedVersion. The descriptor version
    // passed must be existingVersion+1 (the adapter uses descriptor.version()-1 as
    // expectedVersion). After a successful UPDATE, the DB row has version=descriptor.version().
    // ------------------------------------------------------------------

    @Test
    void upsert_updatePath_withMatchingVersion_updatesBoth() throws SQLException {
        String schemaName = schema("upsert_updatePath_withMatchingVersion_updatesBoth");
        migrate(schemaName);

        OperationalConfigR2dbcAdapter adapter = buildAdapter(schemaName);

        // First upsert: INSERT (version=0 → DB stores version=0).
        OperationalConfigDescriptor first = buildDescriptor(0L, ActivationStatus.ACTIVE);
        StepVerifier.create(adapter.upsert(first))
                .assertNext(r -> assertThat(r.id()).isNotNull())
                .verifyComplete();

        // Second upsert: UPDATE path. descriptor.version()=1 → adapter uses expectedVersion=0.
        // The DB row has version=0 so the UPDATE WHERE version=0 matches.
        OperationalConfigDescriptor second = buildDescriptor(1L, ActivationStatus.ACTIVE);
        StepVerifier.create(adapter.upsert(second))
                .assertNext(r -> assertThat(r.version()).isEqualTo(1L))
                .verifyComplete();

        // Verify the root row's version was incremented to 1.
        try (java.sql.Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(
                    "SELECT version FROM \"" + schemaName + "\".wallet_operational_config "
                            + "WHERE is_active = true");
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong("version")).as("updated version in DB").isEqualTo(1L);
        }
    }

    // ------------------------------------------------------------------
    // TC-4 — upsert update path with stale version emits OptimisticLockingFailureException.
    //
    // After an INSERT (DB version=0), calling upsert with descriptor.version()=0 causes
    // the adapter to use expectedVersion=-1 in the WHERE clause, which matches nothing
    // → OptimisticLockingFailureException.
    // ------------------------------------------------------------------

    @Test
    void upsert_updatePath_withStaleVersion_throwsOptimisticLockingFailure() throws SQLException {
        String schemaName = schema("upsert_updatePath_withStaleVersion_throwsOptLock");
        migrate(schemaName);

        OperationalConfigR2dbcAdapter adapter = buildAdapter(schemaName);

        // First upsert: INSERT (version=0 → DB stores version=0).
        OperationalConfigDescriptor first = buildDescriptor(0L, ActivationStatus.ACTIVE);
        StepVerifier.create(adapter.upsert(first))
                .expectNextCount(1)
                .verifyComplete();

        // Pass version=0 on the second call: adapter computes expectedVersion = 0-1 = -1,
        // which does not match the DB's version=0 → optimistic lock failure.
        OperationalConfigDescriptor stale = new OperationalConfigDescriptor(
                UUID.randomUUID(),
                KeyManager.DB_TDE,
                new DbTdeOperationalConfig(
                        "arn:aws:kms:eu-west-1:123456789012:key/" + UUID.randomUUID(),
                        new byte[]{0x05, 0x06},
                        "AES-256-GCM"
                ),
                true,
                ActivationStatus.ACTIVE,
                Optional.of(Instant.now()),
                0L,   // version=0 → adapter uses expectedVersion=-1 (stale)
                "it-test-actor",
                Instant.now()
        );

        StepVerifier.create(adapter.upsert(stale))
                .expectError(OptimisticLockingFailureException.class)
                .verify();
    }

    // ------------------------------------------------------------------
    // TC-5 — canQuerySubtable(DB_TDE) returns true after V4 migration.
    // ------------------------------------------------------------------

    @Test
    void canQuerySubtable_subTableExists_returnsTrue() throws SQLException {
        String schemaName = schema("canQuerySubtable_subTableExists_returnsTrue");
        migrate(schemaName);

        OperationalConfigR2dbcAdapter adapter = buildAdapter(schemaName);

        StepVerifier.create(adapter.canQuerySubtable(KeyManager.DB_TDE))
                .assertNext(result -> assertThat(result).isTrue())
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // TC-6 — findActive after insert returns combined descriptor with sub-table fields.
    //
    // After upsert (is_active=true), findActive() must return an Optional containing a
    // descriptor whose operationalConfig has the correct algorithm, wrappedDek bytes, and
    // columnEncryptionKeyArn that were stored during the INSERT.
    // ------------------------------------------------------------------

    @Test
    void findActive_joinReturnsCombinedDescriptor() throws SQLException {
        String schemaName = schema("findActive_joinReturnsCombinedDescriptor");
        migrate(schemaName);

        OperationalConfigR2dbcAdapter adapter = buildAdapter(schemaName);

        String expectedArn = "arn:aws:kms:eu-west-1:123456789012:key/" + UUID.randomUUID();
        byte[] expectedDek = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
        OperationalConfigDescriptor descriptor = new OperationalConfigDescriptor(
                UUID.randomUUID(),
                KeyManager.DB_TDE,
                new DbTdeOperationalConfig(expectedArn, expectedDek, "AES-256-GCM"),
                true,
                ActivationStatus.ACTIVE,
                Optional.of(Instant.now()),
                0L,
                "it-test-actor",
                Instant.now()
        );

        StepVerifier.create(adapter.upsert(descriptor))
                .expectNextCount(1)
                .verifyComplete();

        StepVerifier.create(adapter.findActive())
                .assertNext(opt -> {
                    assertThat(opt).isPresent();
                    OperationalConfigDescriptor found = opt.get();
                    assertThat(found.keyManager()).isEqualTo(KeyManager.DB_TDE);
                    assertThat(found.isActive()).isTrue();
                    assertThat(found.operationalConfig()).isInstanceOf(DbTdeOperationalConfig.class);

                    DbTdeOperationalConfig dbTde = (DbTdeOperationalConfig) found.operationalConfig();
                    assertThat(dbTde.columnEncryptionKeyArn())
                            .as("columnEncryptionKeyArn")
                            .isEqualTo(expectedArn);
                    assertThat(dbTde.algorithm())
                            .as("algorithm")
                            .isEqualTo("AES-256-GCM");
                    assertThat(Arrays.equals(dbTde.wrappedDek(), expectedDek))
                            .as("wrappedDek bytes preserved")
                            .isTrue();
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // Inner helper: connection factory that fixes search_path on every connection.
    // ------------------------------------------------------------------

    /**
     * Minimal {@link ConnectionFactory} decorator that sets {@code search_path} to a given schema
     * on every acquired connection, mirroring what {@code TenantAwareConnectionFactoryDecorator}
     * does in production but scoped to the per-test schema.
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
