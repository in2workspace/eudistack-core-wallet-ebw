package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.domain.spi.EmailSender;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;

/**
 * EUD-104 ES-04: associating a device is the register -&gt; verify-email -&gt; passkeys
 * pipeline (AD-1, no dedicated {@code /add-device} endpoint), scoped entirely by the
 * tenant resolved from the request (schema-per-tenant, {@code TenantAwareConnectionFactoryDecorator}).
 * This proves that pipeline fails closed across a tenant boundary: the SAME email
 * registered from two different tenants MUST end up as two completely independent
 * accounts — tenant B's find-or-create must never "reuse" tenant A's account — and a
 * passkey created in one tenant MUST NOT be reachable from the other's schema.
 *
 * <p>Same self-contained Testcontainers + two-tenant-schema setup as
 * {@link PasskeyIsolationIT} / {@link PasskeyRevocationIsolationIT}, except {@code TokenSigner}
 * is deliberately NOT mocked here — this test drives the REAL register/verify/passkeys HTTP
 * pipeline (only {@code EmailSender} is mocked, to capture the OTP), because ES-04 is about
 * isolation of that pipeline itself, not of an already-issued token. Those two sibling suites
 * cover GET/DELETE on an existing passkey; neither exercises find-or-create or passkey
 * creation across a tenant boundary, which is exactly EUD-104's gap.
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class RegisterTenantIsolationIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT_1 = "regisoa";
    private static final String TENANT_2 = "regisob";
    private static final String SCHEMA_1 = TENANT_1 + SCHEMA_SUFFIX;
    private static final String SCHEMA_2 = TENANT_2 + SCHEMA_SUFFIX;
    private static final String HOST_1 = TENANT_1 + ".eudistack.net";
    private static final String HOST_2 = TENANT_2 + ".eudistack.net";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("register_tenant_isolation_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/register_tenant_isolation_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/register_tenant_isolation_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @MockitoBean
    EmailSender emailSender;

    @Autowired
    WebTestClient webClient;

    private final Map<String, String> capturedOtps = new ConcurrentHashMap<>();

    @BeforeAll
    static void provisionSchemas() throws SQLException {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + SCHEMA_1);
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + SCHEMA_2);
        }
        runTenantMigrations(jdbcUrl, SCHEMA_1);
        runTenantMigrations(jdbcUrl, SCHEMA_2);
    }

    private static void runTenantMigrations(String jdbcUrl, String schema) {
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    @BeforeEach
    void setUp() throws SQLException {
        cleanTables(SCHEMA_1);
        cleanTables(SCHEMA_2);
        capturedOtps.clear();
        doAnswer(invocation -> {
            String email = invocation.getArgument(0);
            String code = invocation.getArgument(1);
            capturedOtps.put(email, code);
            return Mono.empty();
        }).when(emailSender).sendOtp(anyString(), anyString());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void cleanTables(String schema) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute("DELETE FROM " + schema + ".refresh_token");
            conn.createStatement().execute("DELETE FROM " + schema + ".user_passkey");
            conn.createStatement().execute("DELETE FROM " + schema + ".wallet_user");
        }
    }

    @SuppressWarnings("unchecked")
    private void registerVerifyAndCreatePasskey(String host, String email, String credentialId) {
        webClient.post().uri("/api/v1/auth/register")
                .header("Host", host)
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isOk();

        var otp = capturedOtps.get(email);
        assertThat(otp).as("OTP must have been captured for " + email + " on host " + host).isNotNull();

        var tokens = webClient.post().uri("/api/v1/auth/verify-email")
                .header("Host", host)
                .bodyValue(Map.of("email", email, "code", otp))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();
        var accessToken = (String) tokens.get("accessToken");

        webClient.post().uri("/api/v1/auth/passkeys")
                .header("Host", host)
                .headers(h -> h.setBearerAuth(accessToken))
                .bodyValue(Map.of("credentialId", credentialId, "displayName", "Device on " + host))
                .exchange()
                .expectStatus().isCreated();
    }

    private UUID fetchUserId(String schema, String email) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             var rs = conn.createStatement().executeQuery(
                     "SELECT id FROM " + schema + ".wallet_user WHERE email = '" + email + "'")) {
            return rs.next() ? (UUID) rs.getObject("id") : null;
        }
    }

    private boolean passkeyExistsForCredential(String schema, String credentialId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             var rs = conn.createStatement().executeQuery(
                     "SELECT 1 FROM " + schema + ".user_passkey WHERE credential_id = '" + credentialId + "'")) {
            return rs.next();
        }
    }

    // -------------------------------------------------------------------------
    // ES-04 — same email, two tenants: two independent accounts, no cross-tenant reuse
    // -------------------------------------------------------------------------

    @Test
    void register_sameEmailTwoTenants_createsTwoIndependentAccounts_noCrossTenantReuse()
            throws SQLException {
        var email = "cross-tenant-" + System.nanoTime() + "@example.com";
        var credentialTenant1 = "cred-tenant1-" + System.nanoTime();
        var credentialTenant2 = "cred-tenant2-" + System.nanoTime();

        registerVerifyAndCreatePasskey(HOST_1, email, credentialTenant1);
        registerVerifyAndCreatePasskey(HOST_2, email, credentialTenant2);

        var userIdTenant1 = fetchUserId(SCHEMA_1, email);
        var userIdTenant2 = fetchUserId(SCHEMA_2, email);

        assertThat(userIdTenant1).isNotNull();
        assertThat(userIdTenant2).isNotNull();
        assertThat(userIdTenant1)
                .as("tenant B's find-or-create must NOT reuse tenant A's account for the same email")
                .isNotEqualTo(userIdTenant2);

        // Each tenant's passkey is only reachable from its own schema.
        assertThat(passkeyExistsForCredential(SCHEMA_1, credentialTenant1)).isTrue();
        assertThat(passkeyExistsForCredential(SCHEMA_2, credentialTenant1))
                .as("tenant 1's passkey must not leak into tenant 2's schema")
                .isFalse();
        assertThat(passkeyExistsForCredential(SCHEMA_2, credentialTenant2)).isTrue();
        assertThat(passkeyExistsForCredential(SCHEMA_1, credentialTenant2))
                .as("tenant 2's passkey must not leak into tenant 1's schema")
                .isFalse();
    }
}
