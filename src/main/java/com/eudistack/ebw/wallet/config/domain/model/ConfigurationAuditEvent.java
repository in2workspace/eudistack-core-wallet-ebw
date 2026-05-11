package com.eudistack.ebw.wallet.config.domain.model;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

/**
 * Value Object representing an immutable audit entry for a wallet configuration change.
 *
 * <p>Append-only. Once created, an audit event is never modified.
 * Persisted by {@code ConfigurationAuditPort} to the tenant's audit table.
 */
public final class ConfigurationAuditEvent {

    /**
     * The type of configuration event that occurred.
     */
    public enum Event {
        CONFIG_CREATED,
        CONFIG_UPDATED,
        CONFIG_REJECTED,
        CACHE_INVALIDATION_FAILED
    }

    /**
     * The configuration plane affected by the event.
     */
    public enum Plane {
        DISCOVERY,
        OPERATIONAL
    }

    /**
     * The outcome of the operation that generated the event.
     */
    public enum Outcome {
        PERMIT,
        DENY
    }

    /**
     * Captures the before/after values for a single changed field.
     * Values are type-erased to String to avoid serialization coupling.
     */
    public record FieldDelta(String from, String to) {
    }

    private final String actor;
    private final Event event;
    private final Plane plane;
    private final Map<String, FieldDelta> fieldChanges;
    private final Outcome outcome;
    private final String reason;
    private final String correlationId;
    private final Instant occurredAt;

    private ConfigurationAuditEvent(
            String actor,
            Event event,
            Plane plane,
            Map<String, FieldDelta> fieldChanges,
            Outcome outcome,
            String reason,
            String correlationId,
            Instant occurredAt) {
        this.actor = actor;
        this.event = event;
        this.plane = plane;
        this.fieldChanges = Collections.unmodifiableMap(fieldChanges);
        this.outcome = outcome;
        this.reason = reason;
        this.correlationId = correlationId;
        this.occurredAt = occurredAt;
    }

    public static ConfigurationAuditEvent create(
            String actor,
            Event event,
            Plane plane,
            Map<String, FieldDelta> fieldChanges,
            Outcome outcome,
            String reason,
            String correlationId) {
        return new ConfigurationAuditEvent(
                actor,
                event,
                plane,
                fieldChanges,
                outcome,
                reason,
                correlationId != null ? correlationId : UUID.randomUUID().toString(),
                Instant.now());
    }

    public String getActor() {
        return actor;
    }

    public Event getEvent() {
        return event;
    }

    public Plane getPlane() {
        return plane;
    }

    public Map<String, FieldDelta> getFieldChanges() {
        return fieldChanges;
    }

    public Outcome getOutcome() {
        return outcome;
    }

    public String getReason() {
        return reason;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }
}
