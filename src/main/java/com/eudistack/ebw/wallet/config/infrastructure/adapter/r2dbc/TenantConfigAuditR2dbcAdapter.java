package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent;
import com.eudistack.ebw.wallet.config.domain.model.SchemaName;
import com.eudistack.ebw.wallet.config.domain.port.ConfigurationAuditPort;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

/**
 * Append-only R2DBC implementation of {@link ConfigurationAuditPort}.
 *
 * <p>Inserts a new row into {@code <schemaName>_business_wallet.wallet_config_audit}.
 * The target schema is resolved from {@link ConfigurationAuditEvent#getSchemaName()},
 * which is provided by the writer at call time (AC-3a, AC-3b, AC-4c).
 *
 * <p>The DDL trigger on {@code wallet_config_audit} (Task 8) rejects {@code UPDATE}
 * and {@code DELETE} — this adapter only ever issues {@code INSERT} (AC-3e).
 *
 * <p>The {@code field_changes} JSON column never contains raw secret values — only
 * the enum type names are recorded (AC-3c).
 *
 * <p><strong>Schema strategy:</strong> The adapter uses a dedicated {@link DatabaseClient}
 * backed by the {@code publicSchemaRw} connection factory. The target table is schema-qualified
 * ({@code <schemaName>_business_wallet.wallet_config_audit}) so that the correct tenant
 * schema is always targeted without relying on the Reactor context or
 * {@code TenantAwareConnectionFactoryDecorator} (AD-S2). This approach is compatible with
 * the eventual introduction of {@code TenantSchemaAdapter} (EUDISTACK-2).
 */
public class TenantConfigAuditR2dbcAdapter implements ConfigurationAuditPort {

    private static final Logger log = LoggerFactory.getLogger(TenantConfigAuditR2dbcAdapter.class);

    private static final String SCHEMA_SUFFIX = "_business_wallet";

    private final DatabaseClient databaseClient;
    private final ObjectMapper objectMapper;

    public TenantConfigAuditR2dbcAdapter(DatabaseClient databaseClient, ObjectMapper objectMapper) {
        this.databaseClient = databaseClient;
        this.objectMapper = objectMapper;
    }

    /**
     * Inserts an audit entry into {@code <schemaName>_business_wallet.wallet_config_audit}.
     *
     * @param event the audit event; must not be {@code null} and must have a valid
     *              {@link ConfigurationAuditEvent#getSchemaName()}
     * @return a {@link Mono} that completes on successful insert
     */
    @Override
    public Mono<Void> append(ConfigurationAuditEvent event) {
        return Mono.defer(() -> {
            // SEC-B1: validate the schema name before interpolating it into the table identifier.
            // schemaName flows from the admin PUT path variable / POST body — never trust it here.
            String schemaName = SchemaName.requireValid(event.getSchemaName());
            String qualifiedTable = schemaName + SCHEMA_SUFFIX + ".wallet_config_audit";
            String fieldChangesJson = serializeFieldChanges(event);

            String sql = "INSERT INTO " + qualifiedTable
                    + " (actor, event, plane, field_changes, outcome, reason, correlation_id, occurred_at)"
                    + " VALUES (:actor, :event::text, :plane::text, :fieldChanges::jsonb,"
                    + "        :outcome::text, :reason, :correlationId, :occurredAt)";

            log.debug("Appending audit entry: table={}, event={}, outcome={}",
                    qualifiedTable, event.getEvent(), event.getOutcome());

            DatabaseClient.GenericExecuteSpec spec = databaseClient.sql(sql)
                    .bind("actor", event.getActor() != null ? event.getActor() : "unknown")
                    .bind("event", event.getEvent().name())
                    .bind("plane", event.getPlane().name())
                    .bind("fieldChanges", fieldChangesJson)
                    .bind("outcome", event.getOutcome().name())
                    .bind("correlationId", event.getCorrelationId())
                    .bind("occurredAt", event.getOccurredAt());

            if (event.getReason() != null) {
                spec = spec.bind("reason", event.getReason());
            } else {
                spec = spec.bindNull("reason", String.class);
            }

            return spec.then()
                    .doOnSuccess(v -> log.debug(
                            "Audit entry appended: event={}, correlationId={}",
                            event.getEvent(), event.getCorrelationId()))
                    .doOnError(e -> log.error(
                            "Failed to append audit entry: event={}, correlationId={}, error={}",
                            event.getEvent(), event.getCorrelationId(), e.getMessage()));
        });
    }

    private String serializeFieldChanges(ConfigurationAuditEvent event) {
        try {
            return objectMapper.writeValueAsString(event.getFieldChanges());
        } catch (JsonProcessingException e) {
            log.warn("Failed to serialize field_changes for audit, using empty object: {}",
                    e.getMessage());
            return "{}";
        }
    }
}
