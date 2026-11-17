package com.eudistack.ebw.domain.model.audit;

import com.eudistack.ebw.domain.model.exception.InvalidAuditEntryException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * What a use case knows about an auditable fact: the event type, the object it is about, the outcome
 * and the type's {@code details}. The tenant, actor and correlation id are not part of it: they come
 * from the audit context of the operation.
 *
 * <p>The catalogue rules are enforced on construction: a non-success entry needs a reason from the
 * type's vocabulary, and that reason fixes the result. A detail left {@code null} is omitted.
 */
public record AuditEntry(
        AuditEventType type,
        String source,
        String resource,
        AuditResult result,
        String reason,
        Map<String, Object> details
) {

    public AuditEntry {
        Objects.requireNonNull(type, "type is required");
        Objects.requireNonNull(result, "result is required");
        if (resource == null || resource.isBlank()) {
            throw new InvalidAuditEntryException("An audit entry needs the resource it is about");
        }
        source = source == null || source.isBlank() ? AuditSource.WALLET_EBW : source;
        requireConsistentReason(type, result, reason);
        details = withoutNullValues(details);
    }

    public static AuditEntry success(AuditEventType type, String resource, Map<String, Object> details) {
        return new AuditEntry(type, null, resource, AuditResult.SUCCESS, null, details);
    }

    /** A non-success entry whose result is the one the catalogue fixes for {@code reason} in this type. */
    public static AuditEntry forReason(AuditEventType type, String resource, String reason,
                                       Map<String, Object> details) {
        AuditResult result = type.resultFor(reason).orElseThrow(() -> new InvalidAuditEntryException(
                reason + " is not a reason of " + type.catalogName()));
        return new AuditEntry(type, null, resource, result, reason, details);
    }

    private static void requireConsistentReason(AuditEventType type, AuditResult result, String reason) {
        if (result == AuditResult.SUCCESS) {
            if (reason != null) {
                throw new InvalidAuditEntryException(type.catalogName() + ": a successful entry carries no reason");
            }
            return;
        }
        if (reason == null || reason.isBlank()) {
            throw new InvalidAuditEntryException(type.catalogName() + ": a " + result + " entry needs a reason");
        }
        AuditResult determined = type.resultFor(reason).orElseThrow(() -> new InvalidAuditEntryException(
                reason + " is not a reason of " + type.catalogName()));
        if (determined != result) {
            throw new InvalidAuditEntryException(
                    reason + " determines the result " + determined + " for " + type.catalogName() + ", not " + result);
        }
    }

    private static Map<String, Object> withoutNullValues(Map<String, Object> source) {
        Map<String, Object> copy = new LinkedHashMap<>();
        if (source != null) {
            source.forEach((key, value) -> {
                if (value != null) {
                    copy.put(key, value);
                }
            });
        }
        return Map.copyOf(copy);
    }
}
