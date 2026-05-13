package com.eudistack.ebw.wallet.config.infrastructure.persistence;

import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.PublicSchemaConnectionFactory;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.WalletTenantConfigR2dbcAdapter;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.r2dbc.core.DatabaseClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static io.r2dbc.spi.ConnectionFactoryOptions.DATABASE;
import static io.r2dbc.spi.ConnectionFactoryOptions.DRIVER;
import static io.r2dbc.spi.ConnectionFactoryOptions.HOST;
import static io.r2dbc.spi.ConnectionFactoryOptions.PASSWORD;
import static io.r2dbc.spi.ConnectionFactoryOptions.PORT;
import static io.r2dbc.spi.ConnectionFactoryOptions.USER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Migration / DB-level integration test for {@code public.tenant_wallet_config} — covers T-3
 * (AC-2a, AC-2b, AC-2c, E-7, E-8) from tech-design §2.3.
 *
 * <p><strong>Why this test does NOT use a Spring context.</strong> {@code application.yml} in the
 * test classpath excludes the R2DBC / Flyway auto-configuration so {@code ApplicationTests} can
 * boot without Postgres. So instead of {@code @SpringBootTest}, this test starts a raw
 * {@code postgres:16-alpine} Testcontainers instance (per-class, destructive schema test), applies
 * the production migration SQL ({@code db/migration/V1__Public_schema.sql} for {@code tenant_registry}
 * — required for the FK — then {@code db/migration/V2__Create_tenant_wallet_config.sql}) and asserts
 * the CHECK constraints behave as specified. It then folds in a cheap read-path smoke check against
 * the real adapter ({@code WalletTenantConfigR2dbcAdapter}) over the {@code publicSchema} template.
 *
 * <p>What is asserted against the V2 migration:
 * <ul>
 *   <li>{@code chk_twc_browser_no_key_manager}: INSERT browser + non-null key_manager → rejected.</li>
 *   <li>INSERT browser + key_manager NULL + natural_persons_only=false → accepted.</li>
 *   <li>{@code ON CONFLICT (schema_name) DO NOTHING} re-applied → no-op, no error (idempotent).</li>
 *   <li>{@code chk_twc_wallet_mode}: INSERT wallet_mode='invalid_mode' → rejected.</li>
 *   <li>{@code chk_twc_key_manager}: INSERT server + 'bogus_km' (not kebab-case enum) → rejected.</li>
 * </ul>
 *
 * <p>The {@code server ⇒ key_manager NOT NULL} CHECK (FR-21) is intentionally NOT in V2 — it belongs
 * to US-02's migration (feature-design §4.1, tech-design §3.7 R-6) — so it is not asserted here. The
 * coherence CHECK {@code natural_persons_only = (key_manager='hybrid')} is likewise not present in
 * the V2 file shipped in this Story, so it is not asserted (see handoff note).
 *
 * <p>Tagged {@code integration} → runs under {@code ./gradlew integrationTest} (Docker required).
 */
@Testcontainers
@Tag("integration")
class TenantWalletConfigSchemaMigrationIT {

    private static final String TENANT_SCHEMA_NAME = "acme";
    private static final String TENANT_HOST = "acme.eudiw.example.com";

    @Container
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("ebw_migration_test")
            .withUsername("test")
            .withPassword("test");

    private static ConnectionFactory connectionFactory;
    private static DatabaseClient databaseClient;
    private static WalletTenantConfigR2dbcAdapter readAdapter;

    @BeforeAll
    static void applyMigrations() {
        connectionFactory = ConnectionFactories.get(ConnectionFactoryOptions.builder()
                .option(DRIVER, "postgresql")
                .option(HOST, postgres.getHost())
                .option(PORT, postgres.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT))
                .option(DATABASE, postgres.getDatabaseName())
                .option(USER, postgres.getUsername())
                .option(PASSWORD, postgres.getPassword())
                .build());
        databaseClient = DatabaseClient.create(connectionFactory);

        // Production migrations, in dependency order: tenant_registry (FK target) then tenant_wallet_config.
        executeSql(readClasspath("/db/migration/V1__Public_schema.sql"));
        executeSql(readClasspath("/db/migration/V2__Create_tenant_wallet_config.sql"));

        // Read-path adapter wired exactly as WalletTenantConfigBeans wires it in production:
        // publicSchema wrapper (search_path=public) over the connection factory.
        ConnectionFactory publicSchema = new PublicSchemaConnectionFactory(connectionFactory, "publicSchema-it");
        R2dbcEntityTemplate template = new R2dbcEntityTemplate(
                DatabaseClient.builder().connectionFactory(publicSchema).build(),
                new DefaultReactiveDataAccessStrategy(PostgresDialect.INSTANCE));
        readAdapter = new WalletTenantConfigR2dbcAdapter(template);
    }

    @BeforeEach
    void resetState() {
        // Each test starts from a clean tenant_wallet_config table; tenant_registry holds one tenant.
        databaseClient.sql("DELETE FROM public.tenant_wallet_config").fetch().rowsUpdated().block();
        databaseClient.sql(
                        "INSERT INTO public.tenant_registry (schema_name, display_name) VALUES (:s, :d) "
                                + "ON CONFLICT (schema_name) DO NOTHING")
                .bind("s", TENANT_SCHEMA_NAME)
                .bind("d", "ACME")
                .fetch().rowsUpdated().block();
    }

    // ------------------------------------------------------------------
    // AC-2b / E-7 — browser + non-null key_manager → CHECK violation
    // ------------------------------------------------------------------

    @Test
    void insertBrowserTenantWithKeyManager_isRejectedByCheckConstraint() {
        assertThatThrownBy(() ->
                databaseClient.sql(
                                "INSERT INTO public.tenant_wallet_config "
                                        + "(schema_name, host, wallet_mode, key_manager, natural_persons_only) "
                                        + "VALUES (:s, :h, 'browser', 'db-tde', false)")
                        .bind("s", TENANT_SCHEMA_NAME)
                        .bind("h", TENANT_HOST)
                        .fetch().rowsUpdated().block())
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_twc_browser_no_key_manager");

        // No row was applied.
        Long count = databaseClient.sql("SELECT count(*) FROM public.tenant_wallet_config")
                .map(row -> row.get(0, Long.class)).one().block();
        assertThat(count).isZero();
    }

    // ------------------------------------------------------------------
    // AC-2c — browser + NULL key_manager + natural_persons_only=false → accepted
    // ------------------------------------------------------------------

    @Test
    void insertCoherentBrowserTenant_isAccepted() {
        Long rows = databaseClient.sql(
                        "INSERT INTO public.tenant_wallet_config "
                                + "(schema_name, host, wallet_mode, key_manager, natural_persons_only) "
                                + "VALUES (:s, :h, 'browser', NULL, false)")
                .bind("s", TENANT_SCHEMA_NAME)
                .bind("h", TENANT_HOST)
                .fetch().rowsUpdated().block();
        assertThat(rows).isEqualTo(1L);

        String storedMode = databaseClient.sql(
                        "SELECT wallet_mode FROM public.tenant_wallet_config WHERE schema_name = :s")
                .bind("s", TENANT_SCHEMA_NAME)
                .map(row -> row.get("wallet_mode", String.class)).one().block();
        assertThat(storedMode).isEqualTo("browser");
    }

    // ------------------------------------------------------------------
    // E-8 — ON CONFLICT (schema_name) DO NOTHING re-applied → idempotent no-op
    // ------------------------------------------------------------------

    @Test
    void reInsertingSameRowOnConflictDoNothing_isIdempotentNoOp() {
        String upsert = "INSERT INTO public.tenant_wallet_config "
                + "(schema_name, host, wallet_mode, key_manager, natural_persons_only) "
                + "VALUES (:s, :h, 'browser', NULL, false) ON CONFLICT (schema_name) DO NOTHING";

        Long first = databaseClient.sql(upsert).bind("s", TENANT_SCHEMA_NAME).bind("h", TENANT_HOST)
                .fetch().rowsUpdated().block();
        assertThat(first).isEqualTo(1L);

        // Second application: no error, no row affected, no duplicate.
        Long second = databaseClient.sql(upsert).bind("s", TENANT_SCHEMA_NAME).bind("h", TENANT_HOST)
                .fetch().rowsUpdated().block();
        assertThat(second).isZero();

        Long count = databaseClient.sql("SELECT count(*) FROM public.tenant_wallet_config")
                .map(row -> row.get(0, Long.class)).one().block();
        assertThat(count).isEqualTo(1L);
    }

    // ------------------------------------------------------------------
    // AC-2a — chk_twc_wallet_mode: invalid wallet_mode → rejected
    // ------------------------------------------------------------------

    @Test
    void insertInvalidWalletMode_isRejectedByCheckConstraint() {
        assertThatThrownBy(() ->
                databaseClient.sql(
                                "INSERT INTO public.tenant_wallet_config "
                                        + "(schema_name, host, wallet_mode, key_manager, natural_persons_only) "
                                        + "VALUES (:s, :h, 'invalid_mode', NULL, false)")
                        .bind("s", TENANT_SCHEMA_NAME)
                        .bind("h", TENANT_HOST)
                        .fetch().rowsUpdated().block())
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_twc_wallet_mode");
    }

    // ------------------------------------------------------------------
    // AC-2a — chk_twc_key_manager: non-kebab-case / unknown key_manager → rejected
    // ------------------------------------------------------------------

    @Test
    void insertServerTenantWithUnknownKeyManager_isRejectedByCheckConstraint() {
        assertThatThrownBy(() ->
                databaseClient.sql(
                                "INSERT INTO public.tenant_wallet_config "
                                        + "(schema_name, host, wallet_mode, key_manager, natural_persons_only) "
                                        + "VALUES (:s, :h, 'server', 'bogus_km', false)")
                        .bind("s", TENANT_SCHEMA_NAME)
                        .bind("h", TENANT_HOST)
                        .fetch().rowsUpdated().block())
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_twc_key_manager");
    }

    // ------------------------------------------------------------------
    // Read-path smoke check (nice-to-have): a seeded lowercase host is resolved by the
    // production adapter, with uppercase Host normalised, mapping to a browser descriptor.
    // ------------------------------------------------------------------

    @Test
    void findByHost_resolvesSeededBrowserTenant_andNormalisesUppercaseHost() {
        databaseClient.sql(
                        "INSERT INTO public.tenant_wallet_config "
                                + "(schema_name, host, wallet_mode, key_manager, natural_persons_only, version) "
                                + "VALUES (:s, :h, 'browser', NULL, false, 5)")
                .bind("s", TENANT_SCHEMA_NAME)
                .bind("h", TENANT_HOST)
                .fetch().rowsUpdated().block();

        StepVerifier.create(readAdapter.findByHost(TENANT_HOST.toUpperCase()))
                .assertNext(descriptor -> {
                    assertThat(descriptor.getSchemaName()).isEqualTo(TENANT_SCHEMA_NAME);
                    assertThat(descriptor.getHost()).isEqualTo(TENANT_HOST);
                    assertThat(descriptor.getWalletMode()).isEqualTo(WalletMode.BROWSER);
                    assertThat(descriptor.getKeyManager()).isEmpty();
                    assertThat(descriptor.isNaturalPersonsOnly()).isFalse();
                    assertThat(descriptor.getSupportedCredentials()).isEmpty();
                    assertThat(descriptor.getVersion()).isEqualTo(5L);
                })
                .verifyComplete();

        StepVerifier.create(readAdapter.findByHost("not.seeded.example.com"))
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static String readClasspath(String path) {
        try (var in = TenantWalletConfigSchemaMigrationIT.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException("Migration resource not found on classpath: " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Executes a SQL script statement-by-statement. The V1/V2 migration files are simple DDL with no
     * PL/pgSQL bodies, so: strip every {@code --} line comment first (some comments contain a
     * {@code ;}, so they must go before the split), then split on {@code ;}. Avoids depending on
     * Flyway here.
     */
    private static void executeSql(String script) {
        String withoutComments = Arrays.stream(script.split("\n"))
                .map(line -> {
                    int commentStart = line.indexOf("--");
                    return commentStart >= 0 ? line.substring(0, commentStart) : line;
                })
                .reduce((a, b) -> a + "\n" + b)
                .orElse("");

        Arrays.stream(withoutComments.split(";"))
                .map(String::strip)
                .filter(stmt -> !stmt.isEmpty())
                .forEach(stmt -> databaseClient.sql(stmt).fetch().rowsUpdated().block());
    }
}
