package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalAuditEvent;
import com.eudistack.ebw.wallet.config.domain.port.OperationalConfigAuditPort;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

/**
 * R2DBC implementation of {@link OperationalConfigAuditPort}.
 *
 * <p>Appends one row per call to {@code wallet_config_audit} with {@code plane='operational'}.
 * The table is governed by the append-only trigger {@code trg_wallet_config_audit_append_only}
 * (delivered by EUDISTACK-412 V3 migration), which rejects any {@code UPDATE} or {@code DELETE}.
 *
 * <h2>Transaction isolation — AD-S4</h2>
 * Each call to {@link #recordPermit} or {@link #recordDeny} is wrapped in the
 * {@code auditTransactionalOperator} (a {@link TransactionalOperator} configured with
 * {@code PROPAGATION_REQUIRES_NEW}, provisioned by {@code OperationalConfigBeans} in Task 9).
 * This guarantees that:
 * <ul>
 *   <li>A {@code DENY} audit row persists even if the outer writer transaction is rolled back
 *       (AC-4c, AC-6).</li>
 *   <li>A {@code PERMIT} audit row is committed independently of the outer transaction (AC-4b).</li>
 * </ul>
 *
 * <h2>JSONB serialization</h2>
 * {@link OperationalAuditEvent#fieldChanges()} is serialized to a JSON string via Jackson
 * {@link ObjectMapper}. The SQL casts the bound {@code String} parameter via
 * {@code ::jsonb} so PostgreSQL validates the JSON structure at insert time.
 *
 * <h2>Byte-array tripwire — AC-4d</h2>
 * Before issuing the INSERT, the adapter scans every {@link OperationalAuditEvent.FieldChange}
 * in {@code event.fieldChanges()}. If any {@code before} or {@code after} value matches the
 * pattern of a raw Java byte-array {@code toString()} (i.e. starts with {@code "[B@"} followed
 * by hexadecimal characters), the method throws {@link IllegalStateException} and NO row is
 * written. This is a defensive tripwire against a programmer error where an unredacted
 * {@code byte[]} value leaks into the audit log (the correct path uses
 * {@link OperationalAuditEvent#withSecretFieldRedacted(String, boolean)}).
 *
 * <p>This adapter is <strong>not</strong> annotated with {@code @Component}. It is instantiated
 * by {@code OperationalConfigBeans} (Task 9) following the same pattern as
 * {@code WalletTenantConfigR2dbcAdapter}.
 */
public class OperationalConfigAuditR2dbcAdapter implements OperationalConfigAuditPort {

    private static final Logger log = LoggerFactory.getLogger(OperationalConfigAuditR2dbcAdapter.class);

    /**
     * Regex pattern that matches the default Java byte-array {@code toString()} format.
     * Arrays of type {@code byte[]} render as {@code [B@<hex>} (e.g. {@code [B@1a2b3c4d}).
     */
    private static final String BYTE_ARRAY_TOSTRING_PREFIX = "[B@";

    /**
     * INSERT SQL matching the {@code wallet_config_audit} schema delivered by
     * {@code db/tenant/V3__Wallet_config_audit.sql} (EUDISTACK-412).
     *
     * <p>Column set: {@code id, actor, event, plane, field_changes, outcome, reason,
     * correlation_id, occurred_at}. The {@code ::jsonb} cast in the SQL lets PostgreSQL
     * validate the JSON structure at insert time; the Java side binds a plain {@code String}.
     */
    private static final String INSERT_AUDIT_SQL =
            "INSERT INTO wallet_config_audit "
            + "(id, actor, event, plane, field_changes, outcome, reason, correlation_id, occurred_at) "
            + "VALUES (:id, :actor, :event, :plane, :fieldChanges::jsonb, "
            + "        :outcome, :reason, :correlationId, now())";

    private final DatabaseClient databaseClient;
    private final TransactionalOperator auditTransactionalOperator;
    private final ObjectMapper objectMapper;

    /**
     * Constructs the adapter.
     *
     * @param databaseClient             the default (tenant-aware) client; its underlying
     *                                   {@code ConnectionFactory} is decorated by
     *                                   {@code TenantAwareConnectionFactoryDecorator}
     * @param auditTransactionalOperator a {@link TransactionalOperator} configured with
     *                                   {@code PROPAGATION_REQUIRES_NEW} — provisioned by
     *                                   {@code OperationalConfigBeans} (Task 9)
     * @param objectMapper               Spring Boot's auto-configured Jackson mapper, used to
     *                                   serialize {@link OperationalAuditEvent#fieldChanges()}
     *                                   to a JSON string for JSONB persistence
     */
    public OperationalConfigAuditR2dbcAdapter(
            DatabaseClient databaseClient,
            TransactionalOperator auditTransactionalOperator,
            ObjectMapper objectMapper) {
        this.databaseClient = databaseClient;
        this.auditTransactionalOperator = auditTransactionalOperator;
        this.objectMapper = objectMapper;
    }

    /**
     * Appends a {@code PERMIT} outcome row to {@code wallet_config_audit}.
     *
     * <p>Runs inside a {@code PROPAGATION_REQUIRES_NEW} transaction so the audit record is
     * committed independently of the outer writer transaction (AD-S4).
     *
     * @param event the audit event to persist; {@link OperationalAuditEvent#outcome()} must be
     *              {@link OperationalAuditEvent.Outcome#PERMIT}
     * @return a {@link Mono} that completes empty on success, or signals an error on failure
     */
    @Override
    public Mono<Void> recordPermit(OperationalAuditEvent event) {
        return insert(event);
    }

    /**
     * Appends a {@code DENY} outcome row to {@code wallet_config_audit}.
     *
     * <p>Runs inside a {@code PROPAGATION_REQUIRES_NEW} transaction so the audit record persists
     * even when the main writer transaction has been rolled back (AD-S4, AC-4c, AC-6).
     *
     * @param event the audit event to persist; {@link OperationalAuditEvent#outcome()} must be
     *              {@link OperationalAuditEvent.Outcome#DENY}
     * @return a {@link Mono} that completes empty on success, or signals an error on failure
     */
    @Override
    public Mono<Void> recordDeny(OperationalAuditEvent event) {
        return insert(event);
    }

    // --- Private helpers ---

    /**
     * Core INSERT logic shared by both public methods.
     *
     * <p>Steps:
     * <ol>
     *   <li>Run the byte-array tripwire on {@code event.fieldChanges()}.</li>
     *   <li>Serialize {@code fieldChanges} to a JSON string.</li>
     *   <li>Bind all parameters and execute the INSERT inside
     *       {@code auditTransactionalOperator.execute()} ({@code REQUIRES_NEW}).</li>
     * </ol>
     */
    private Mono<Void> insert(OperationalAuditEvent event) {
        return Mono.fromCallable(() -> {
                    assertNoUnredactedByteArrays(event.fieldChanges());
                    return serializeFieldChanges(event.fieldChanges());
                })
                .flatMap(fieldChangesJson -> {
                    DatabaseClient.GenericExecuteSpec spec = databaseClient.sql(INSERT_AUDIT_SQL)
                            .bind("id", UUID.randomUUID())
                            .bind("actor", event.actor())
                            .bind("event", event.event().getValue())
                            .bind("plane", event.plane())
                            .bind("fieldChanges", fieldChangesJson)
                            .bind("outcome", event.outcome().name())
                            .bind("correlationId", event.correlationId());
                    // reason is optional — bind null when absent.
                    spec = event.reason().isPresent()
                            ? spec.bind("reason", event.reason().get())
                            : spec.bindNull("reason", String.class);
                    final DatabaseClient.GenericExecuteSpec finalSpec = spec;
                    return auditTransactionalOperator.execute(tx ->
                            finalSpec.fetch()
                                    .rowsUpdated()
                                    .doOnNext(rows -> log.debug(
                                            "audit INSERT: outcome={} correlationId={} rowsAffected={}",
                                            event.outcome(), event.correlationId(), rows))
                    ).then();
                });
    }

    /**
     * Scans each {@link OperationalAuditEvent.FieldChange} in {@code fieldChanges} and throws
     * {@link IllegalStateException} if any {@code before} or {@code after} value looks like the
     * default Java byte-array {@code toString()} representation ({@code [B@<hex>}).
     *
     * <p>This is a defensive programmer-error tripwire (AC-4d). If triggered, NO row is written.
     *
     * @param fieldChanges the list to inspect
     * @throws IllegalStateException if an unredacted byte-array value is detected
     */
    private static void assertNoUnredactedByteArrays(
            List<OperationalAuditEvent.FieldChange> fieldChanges) {
        for (OperationalAuditEvent.FieldChange change : fieldChanges) {
            checkValue(change.field(), "before", change.before());
            checkValue(change.field(), "after", change.after());
        }
    }

    private static void checkValue(String field, String slot, String value) {
        if (value != null && looksLikeByteArrayToString(value)) {
            throw new IllegalStateException(
                    "programmer error: unredacted byte[] in FieldChange for field="
                            + field + " slot=" + slot
                            + "; use OperationalAuditEvent.withSecretFieldRedacted() instead");
        }
    }

    private static boolean looksLikeByteArrayToString(String value) {
        if (!value.startsWith(BYTE_ARRAY_TOSTRING_PREFIX)) {
            return false;
        }
        // After "[B@" the remainder must be non-empty hex characters (0-9, a-f, A-F).
        String suffix = value.substring(BYTE_ARRAY_TOSTRING_PREFIX.length());
        if (suffix.isEmpty()) {
            return false;
        }
        for (char c : suffix.toCharArray()) {
            if (!isHexChar(c)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isHexChar(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /**
     * Serializes the list of {@link OperationalAuditEvent.FieldChange} instances to a JSON string.
     *
     * @param fieldChanges the list to serialize
     * @return a non-null JSON string (may be {@code "[]"} for an empty list)
     * @throws IllegalStateException wrapping a {@link JsonProcessingException} on serialization
     *                               failure (should never happen for well-formed records)
     */
    private String serializeFieldChanges(List<OperationalAuditEvent.FieldChange> fieldChanges) {
        try {
            return objectMapper.writeValueAsString(fieldChanges);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize fieldChanges to JSON", e);
        }
    }
}
