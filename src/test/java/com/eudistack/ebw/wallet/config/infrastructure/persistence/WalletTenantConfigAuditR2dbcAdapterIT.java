package com.eudistack.ebw.wallet.config.infrastructure.persistence;

import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.TenantConfigAuditR2dbcAdapter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.postgresql.PostgresqlConnectionConfiguration;
import io.r2dbc.postgresql.PostgresqlConnectionFactory;
import io.r2dbc.spi.ConnectionFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.r2dbc.core.DatabaseClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link TenantConfigAuditR2dbcAdapter}.
 *
 * <p>Covers T-9 (AC-3a, AC-3c) from tech-design §2.3.
 *
 * <p>Uses Testcontainers PostgreSQL. The adapter is instantiated directly (no Spring context)
 * to avoid the full application context loading overhead. This is consistent with the
 * hexagonal principle that infrastructure adapters can be tested in isolation.
 *
 * <p>Note: AC-3e (triggers blocking UPDATE/DELETE) requires the DDL triggers introduced in
 * Task 8. This test verifies the adapter's append-only contract at the code level.
 */
@Testcontainers
@Tag("integration")
class WalletTenantConfigAuditR2dbcAdapterIT {

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("ebw_audit_it")
                    .withUsername("it_user")
                    .withPassword("it_pass");

    private static final String TEST_SCHEMA = "acme_audit_it";
    private static final String TENANT_SCHEMA = TEST_SCHEMA + "_business_wallet";
    private static final String AUDIT_TABLE = TENANT_SCHEMA + ".wallet_config_audit";

    private static DatabaseClient dbClient;
    private TenantConfigAuditR2dbcAdapter adapter;

    @BeforeAll
    static void setUpConnection() {
        ConnectionFactory connectionFactory = new PostgresqlConnectionFactory(
                PostgresqlConnectionConfiguration.builder()
                        .host(postgres.getHost())
                        .port(postgres.getMappedPort(5432))
                        .database("ebw_audit_it")
                        .username("it_user")
                        .password("it_pass")
                        .build());

        dbClient = DatabaseClient.create(connectionFactory);

        // Create tenant schema and audit table
        dbClient.sql("CREATE SCHEMA IF NOT EXISTS " + TENANT_SCHEMA)
                .then()
                .block();

        dbClient.sql("CREATE TABLE IF NOT EXISTS " + AUDIT_TABLE + " ("
                + "id UUID PRIMARY KEY DEFAULT gen_random_uuid(), "
                + "actor VARCHAR(255), "
                + "event TEXT, "
                + "plane TEXT, "
                + "field_changes JSONB, "
                + "outcome TEXT, "
                + "reason TEXT, "
                + "correlation_id VARCHAR(255), "
                + "occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
                + ")")
                .then()
                .block();
    }

    @BeforeEach
    void setUpAdapter() {
        adapter = new TenantConfigAuditR2dbcAdapter(dbClient, new ObjectMapper());
    }

    // ------------------------------------------------------------------
    // T-9: append() inserts audit row with correct fields (AC-3a, AC-3c)
    // ------------------------------------------------------------------

    /**
     * T-9: {@code append()} inserts a row with all required fields correctly populated.
     *
     * <p>Verifies:
     * <ul>
     *   <li>Row is inserted after a single {@code append()} call.</li>
     *   <li>{@code actor}, {@code event}, {@code outcome}, {@code correlation_id} match the event.</li>
     *   <li>{@code field_changes} (jsonb) does not contain raw secrets (AC-3c).</li>
     * </ul>
     */
    @Test
    void append_browserConfigCreated_insertsRowWithCorrectFields() {
        // Given
        String actor = "devops@example.com";
        String correlationId = "corr-audit-t9-001";
        Map<String, ConfigurationAuditEvent.FieldDelta> fieldChanges = Map.of(
                "wallet_mode", new ConfigurationAuditEvent.FieldDelta(null, "browser"),
                "key_manager", new ConfigurationAuditEvent.FieldDelta(null, null));

        ConfigurationAuditEvent event = ConfigurationAuditEvent.create(
                TEST_SCHEMA,
                actor,
                ConfigurationAuditEvent.Event.CONFIG_CREATED,
                ConfigurationAuditEvent.Plane.DISCOVERY,
                fieldChanges,
                ConfigurationAuditEvent.Outcome.PERMIT,
                null,
                correlationId);

        // When
        StepVerifier.create(adapter.append(event))
                .verifyComplete();

        // Then: row exists with correct content
        Map<String, Object> row = dbClient
                .sql("SELECT actor, event, outcome, correlation_id, field_changes::text "
                        + "FROM " + AUDIT_TABLE
                        + " WHERE correlation_id = :corrId")
                .bind("corrId", correlationId)
                .fetch()
                .one()
                .block();

        assertThat(row).isNotNull();
        assertThat(row.get("actor")).isEqualTo(actor);
        assertThat(row.get("event")).isEqualTo("CONFIG_CREATED");
        assertThat(row.get("outcome")).isEqualTo("PERMIT");
        assertThat(row.get("correlation_id")).isEqualTo(correlationId);

        // AC-3c: field_changes must only contain enum names, no raw secret values
        String fieldChangesJson = (String) row.get("field_changes");
        assertThat(fieldChangesJson).doesNotContain("password");
        assertThat(fieldChangesJson).doesNotContain("secret");
        assertThat(fieldChangesJson).doesNotContain("token");
    }

    // ------------------------------------------------------------------
    // T-9: CACHE_INVALIDATION_FAILED event → row with DENY outcome (AC-4c)
    // ------------------------------------------------------------------

    /**
     * T-9 (variant): {@code append()} handles the {@code CACHE_INVALIDATION_FAILED} event.
     *
     * <p>Verifies that a failure event is correctly stored with {@code DENY} outcome and
     * a non-null reason (AC-4c).
     */
    @Test
    void append_cacheInvalidationFailed_insertsRowWithDenyOutcome() {
        // Given
        String correlationId = "corr-cache-fail-t9-001";
        ConfigurationAuditEvent event = ConfigurationAuditEvent.create(
                TEST_SCHEMA,
                "system",
                ConfigurationAuditEvent.Event.CACHE_INVALIDATION_FAILED,
                ConfigurationAuditEvent.Plane.DISCOVERY,
                Collections.emptyMap(),
                ConfigurationAuditEvent.Outcome.DENY,
                "AWS CloudFront timeout after 3 retries",
                correlationId);

        // When
        StepVerifier.create(adapter.append(event))
                .verifyComplete();

        // Then
        Map<String, Object> row = dbClient
                .sql("SELECT event, outcome, reason FROM " + AUDIT_TABLE
                        + " WHERE correlation_id = :corrId")
                .bind("corrId", correlationId)
                .fetch()
                .one()
                .block();

        assertThat(row).isNotNull();
        assertThat(row.get("event")).isEqualTo("CACHE_INVALIDATION_FAILED");
        assertThat(row.get("outcome")).isEqualTo("DENY");
        assertThat(row.get("reason")).asString().contains("CloudFront");
    }

    // ------------------------------------------------------------------
    // T-9: append-only — two successive calls produce two distinct rows (AC-3e scope)
    // ------------------------------------------------------------------

    /**
     * T-9 (AC-3e scope): Two successive {@code append()} calls create two distinct rows.
     *
     * <p>Note: The full AC-3e trigger enforcement (rejecting UPDATE/DELETE at DB level)
     * requires the DDL triggers from Task 8. This test verifies the adapter's append-only
     * contract at the code level: each call inserts a new row independently.
     */
    @Test
    void append_calledTwice_createsTwoDistinctRows() {
        // Given
        String corrId1 = "corr-append-t9-1";
        String corrId2 = "corr-append-t9-2";

        ConfigurationAuditEvent event1 = ConfigurationAuditEvent.create(
                TEST_SCHEMA, "actor1", ConfigurationAuditEvent.Event.CONFIG_CREATED,
                ConfigurationAuditEvent.Plane.DISCOVERY, Collections.emptyMap(),
                ConfigurationAuditEvent.Outcome.PERMIT, null, corrId1);

        ConfigurationAuditEvent event2 = ConfigurationAuditEvent.create(
                TEST_SCHEMA, "actor2", ConfigurationAuditEvent.Event.CONFIG_UPDATED,
                ConfigurationAuditEvent.Plane.DISCOVERY, Collections.emptyMap(),
                ConfigurationAuditEvent.Outcome.PERMIT, null, corrId2);

        // When
        StepVerifier.create(adapter.append(event1).then(adapter.append(event2)))
                .verifyComplete();

        // Then: two distinct rows exist (each append inserts independently)
        Long count = dbClient
                .sql("SELECT COUNT(*) FROM " + AUDIT_TABLE
                        + " WHERE correlation_id IN (:c1, :c2)")
                .bind("c1", corrId1)
                .bind("c2", corrId2)
                .map((row, meta) -> row.get(0, Long.class))
                .one()
                .block();

        assertThat(count).isEqualTo(2L);
    }
}
