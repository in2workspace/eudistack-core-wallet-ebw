package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import com.eudistack.ebw.support.SoftwareAuthenticator;
import com.eudistack.ebw.support.WalletAuthClient;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import reactor.core.publisher.Mono;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;

/**
 * Base class for integration tests.
 *
 * <p><b>Shared-container pattern (intentional).</b> Instead of the Testcontainers JUnit 5
 * {@code @Testcontainers} / {@code @Container} annotations — which give per-class container
 * lifecycle — this class starts a <em>single</em> PostgreSQL container once per JVM via a
 * static initializer and reuses it across every integration test class in the suite. The
 * container is never explicitly stopped; the Testcontainers Ryuk reaper cleans it up when the
 * JVM exits.
 *
 * <p>Why: Postgres startup takes roughly 5 seconds. Amortizing that cost across the whole
 * integration suite (currently four {@code Credential*} and two auth test classes) keeps the
 * suite fast enough to run on every push without sacrificing isolation, because:
 * <ul>
 *   <li>Each test allocates a distinct user via an email suffix of {@code System.nanoTime()},
 *       so state from one test cannot leak into another via primary-key collisions.</li>
 *   <li>Flyway migrations run once on the first Spring context load and are idempotent
 *       thereafter (CREATE TABLE IF NOT EXISTS semantics at the schema level via the
 *       {@code ebw} namespace).</li>
 *   <li>Every test class extends this base, so they all share the same container instance
 *       and the same Spring context cache — no cross-context container churn.</li>
 * </ul>
 *
 * <p>If future tests require strict per-class DB isolation (e.g. a destructive schema
 * migration test), switch that specific test class back to the {@code @Testcontainers} +
 * {@code @Container} pattern with a per-class static field rather than changing the base.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Tag("integration")
public abstract class IntegrationTestBase {

    /**
     * Fixed tenant for the whole suite. {@code TenantAwareConnectionFactoryDecorator}
     * routes every R2DBC connection to {@code <tenant>_business_wallet} based on the
     * tenant resolved from the request (see {@link #addTenantHeader()}) — without a
     * resolvable tenant, every query falls back to the schema-less default and
     * {@code wallet_user}/{@code wallet_credential}/etc. do not exist there: those
     * tables live per-tenant since the schema-per-tenant migration (EUDISTACK-480/412).
     */
    protected static final String TEST_TENANT = "integrationtest";
    private static final String TEST_TENANT_SCHEMA = TEST_TENANT + "_business_wallet";

    static final PostgreSQLContainer<?> postgres;

    static {
        postgres = new PostgreSQLContainer<>("postgres:16-alpine")
                .withDatabaseName("ebw_test")
                .withUsername("test")
                .withPassword("test");
        postgres.start();
        provisionTenantSchema();
    }

    /**
     * Creates the {@code integrationtest_business_wallet} schema and applies the
     * {@code db/tenant} Flyway migrations to it, mirroring what
     * {@code TenantSchemaFlywayMigrator} does per-tenant in production. Run once,
     * directly via JDBC/Flyway, independent of the Spring context (which is not up
     * yet at static-init time).
     */
    private static void provisionTenantSchema() {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE SCHEMA IF NOT EXISTS " + TEST_TENANT_SCHEMA);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to create tenant schema: " + TEST_TENANT_SCHEMA, e);
        }

        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(TEST_TENANT_SCHEMA)
                .schemas(TEST_TENANT_SCHEMA)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            WalletAuthClient.configureRelyingParty(conn, TEST_TENANT_SCHEMA, TEST_TENANT + ".eudistack.test",
                    "https://" + TEST_TENANT + ".eudistack.test");
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to configure the WebAuthn Relying Party", e);
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432) + "/ebw_test?schema=ebw");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () -> postgres.getJdbcUrl() + "&schema=ebw");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "ebw");
    }

    @Autowired
    protected WebTestClient webClient;

    /**
     * Attaches the {@code X-Tenant} header to every request the shared {@link #webClient}
     * sends, so {@code TenantDomainWebFilter} resolves {@link #TEST_TENANT} and R2DBC
     * queries land in {@link #TEST_TENANT_SCHEMA}. Requires
     * {@code ebw.security.trust-forwarded-host=true} (set in application-integration.yaml)
     * since the header is only honoured under that flag. Runs before any subclass
     * {@code @BeforeEach} (JUnit 5 executes superclass callbacks first).
     */
    @BeforeEach
    void addTenantHeader() {
        webClient = webClient.mutate()
                .defaultHeader(TenantDomainWebFilter.HEADER_X_TENANT, TEST_TENANT)
                .build();
        clearIpRateLimits();
    }

    /** The per-IP counters live in the shared database, so they would carry over from one test to the next. */
    private static void clearIpRateLimits() {
        sql("DELETE FROM public.ip_rate_limit");
    }

    @MockitoBean
    protected EmailSender emailSender;

    /** Stores the last OTP sent per email address */
    protected final Map<String, String> capturedOtps = new ConcurrentHashMap<>();

    protected void setupEmailCapture() {
        doAnswer(invocation -> {
            String email = invocation.getArgument(0);
            String code = invocation.getArgument(1);
            capturedOtps.put(email, code);
            return Mono.empty();
        }).when(emailSender).sendOtp(anyString(), anyString());
        lenient().when(emailSender.sendNewPasskeyNotice(anyString())).thenReturn(Mono.empty());
    }

    /** Origin of the Wallet App of {@link #TEST_TENANT}; its Relying Party is {@link #TEST_RP_ID}. */
    protected static final String TEST_ORIGIN = "https://" + TEST_TENANT + ".eudistack.test";
    protected static final String TEST_RP_ID = TEST_TENANT + ".eudistack.test";

    /** Client of the registration and access API for {@link #TEST_TENANT}. */
    protected WalletAuthClient authClient() {
        setupEmailCapture();
        return new WalletAuthClient(webClient, capturedOtps, h -> { }, TEST_ORIGIN);
    }

    /**
     * Access token of a session opened through the real flow: email code, registration ticket and a
     * verified passkey registration with a software authenticator.
     */
    protected String getAccessToken(String email) {
        return authClient().signUp(email, new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
    }

    /** Runs SQL in the test tenant schema (fixtures and assertions on rows the API does not expose). */
    protected static void sql(String statement) {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             Statement stmt = conn.createStatement()) {
            stmt.execute("SET search_path TO " + TEST_TENANT_SCHEMA);
            stmt.execute(statement);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Query in the test tenant schema; one map per row, keyed by lower-case column label. */
    protected static java.util.List<Map<String, Object>> query(String select) {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             Statement stmt = conn.createStatement()) {
            stmt.execute("SET search_path TO " + TEST_TENANT_SCHEMA);
            try (var rs = stmt.executeQuery(select)) {
                var rows = new java.util.ArrayList<Map<String, Object>>();
                var meta = rs.getMetaData();
                while (rs.next()) {
                    var row = new java.util.HashMap<String, Object>();
                    for (int i = 1; i <= meta.getColumnCount(); i++) {
                        row.put(meta.getColumnLabel(i).toLowerCase(), rs.getObject(i));
                    }
                    rows.add(row);
                }
                return rows;
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
