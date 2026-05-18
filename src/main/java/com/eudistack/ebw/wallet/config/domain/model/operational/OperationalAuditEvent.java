package com.eudistack.ebw.wallet.config.domain.model.operational;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable domain event representing one entry in the operational-config audit log
 * ({@code wallet_config_audit} with {@code plane='operational'}).
 *
 * <p>Built by {@code OperationalConfigWriter} before delegating to
 * {@code OperationalConfigAuditPort}. Consumed by {@code OperationalConfigAuditR2dbcAdapter},
 * which serializes it to {@code wallet_config_audit}.
 *
 * <p>Security invariant: fields classified as secrets ({@code wrapped_dek} and any future
 * {@code wrapped_*} / {@code *_secret*} fields) must never appear as actual values in
 * {@link FieldChange#before()} or {@link FieldChange#after()}. Use
 * {@link #withSecretFieldRedacted(String, boolean)} to construct safe {@link FieldChange}
 * instances for those fields (AC-4d).
 */
public record OperationalAuditEvent(
        String actor,
        EventType event,
        String plane,
        Outcome outcome,
        List<FieldChange> fieldChanges,
        Optional<String> reason,
        String correlationId,
        Instant occurredAt
) {

    /** The fixed plane label written to {@code wallet_config_audit.plane}. */
    public static final String OPERATIONAL_PLANE = "operational";

    /**
     * Compact constructor — validates required fields and freezes the field-changes list.
     *
     * @throws NullPointerException if any required field is null
     */
    public OperationalAuditEvent {
        Objects.requireNonNull(actor, "actor must not be null");
        Objects.requireNonNull(event, "event must not be null");
        Objects.requireNonNull(plane, "plane must not be null");
        Objects.requireNonNull(outcome, "outcome must not be null");
        Objects.requireNonNull(fieldChanges, "fieldChanges must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        Objects.requireNonNull(correlationId, "correlationId must not be null");
        Objects.requireNonNull(occurredAt, "occurredAt must not be null");
        fieldChanges = List.copyOf(fieldChanges);
    }

    // -------------------------------------------------------------------------
    // Event type and outcome enumerations
    // -------------------------------------------------------------------------

    /**
     * Identifies the kind of audit event.
     *
     * <p>Serializes to the dot-separated string used in {@code wallet_config_audit.event}.
     */
    public enum EventType {

        CONFIG_APPLIED("config.applied"),
        CONFIG_REJECTED("config.rejected"),
        CONNECTIVITY_VERIFIED("connectivity.verified"),
        CONNECTIVITY_FAILED("connectivity.failed");

        private final String value;

        EventType(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * PBAC-style outcome of the audited operation.
     */
    public enum Outcome {
        PERMIT,
        DENY
    }

    // -------------------------------------------------------------------------
    // FieldChange inner record
    // -------------------------------------------------------------------------

    /**
     * Captures the before/after state of a single field in the operational configuration.
     *
     * <p>For secret fields, {@code before} and {@code after} must always be
     * {@code "<redacted>"} — never the actual value (AC-4d).
     *
     * @param field   the logical field name (e.g. {@code "wrapped_dek"})
     * @param before  the previous value, or {@code "<redacted>"} for secret fields, or
     *                {@code null} if the field did not exist before the event
     * @param after   the new value, or {@code "<redacted>"} for secret fields
     * @param changed {@code true} if the value changed relative to the previous state
     */
    public record FieldChange(
            String field,
            String before,
            String after,
            boolean changed
    ) {

        private static final String REDACTED = "<redacted>";

        /**
         * Compact constructor — validates that field name is non-null.
         */
        public FieldChange {
            Objects.requireNonNull(field, "field must not be null");
        }
    }

    // -------------------------------------------------------------------------
    // Factory helpers
    // -------------------------------------------------------------------------

    /**
     * Constructs a {@link FieldChange} for a secret field, unconditionally using
     * {@code "<redacted>"} as both {@code before} and {@code after} values.
     *
     * <p>Use this method for any field that contains cryptographic key material (e.g.
     * {@code wrapped_dek}, {@code wrapped_client_secret}) to guarantee AC-4d compliance.
     *
     * @param field   the logical field name
     * @param changed whether the secret value changed (the fact of change is not sensitive)
     * @return a {@link FieldChange} with redacted values
     */
    public static FieldChange withSecretFieldRedacted(String field, boolean changed) {
        return new FieldChange(field, FieldChange.REDACTED, FieldChange.REDACTED, changed);
    }

    /**
     * Constructs a {@link FieldChange} for a non-secret field.
     *
     * @param field   the logical field name
     * @param before  the previous value (use {@code null} if the field did not previously exist)
     * @param after   the new value
     * @param changed whether the value changed
     * @return a {@link FieldChange} with plaintext values
     */
    public static FieldChange withPlaintextField(
            String field, String before, String after, boolean changed) {
        return new FieldChange(field, before, after, changed);
    }
}
