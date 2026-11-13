package com.eudistack.ebw.domain.model.audit;

import java.util.Optional;
import java.util.Set;

/**
 * The audit event types the Wallet EBW produces, with the {@code action} and the {@code reason}
 * vocabulary that catalogue 2.2.0 fixes for each. The audit API rejects an event whose action differs,
 * or whose reason is outside the type's vocabulary or contradicts the result the reason determines, so
 * those rules are enforced here before an event can be built.
 */
public enum AuditEventType {

    EXTERNAL_SYSTEM_ACCESS("ExternalSystemAccess", "AccessExternalSystem",
            Set.of("AuthenticationRejected", "SourceNotTrusted"),
            Set.of("ErrorResponse", "InvalidResponse", "Timeout", "Unreachable"));

    private final String catalogName;
    private final String action;
    private final Set<String> deniedReasons;
    private final Set<String> failureReasons;

    AuditEventType(String catalogName, String action, Set<String> deniedReasons, Set<String> failureReasons) {
        this.catalogName = catalogName;
        this.action = action;
        this.deniedReasons = deniedReasons;
        this.failureReasons = failureReasons;
    }

    public String catalogName() {
        return catalogName;
    }

    public String action() {
        return action;
    }

    /** The result a reason determines for this type, or empty when the reason is outside its vocabulary. */
    public Optional<AuditResult> resultFor(String reason) {
        if (deniedReasons.contains(reason)) {
            return Optional.of(AuditResult.DENIED);
        }
        if (failureReasons.contains(reason)) {
            return Optional.of(AuditResult.FAILURE);
        }
        return Optional.empty();
    }
}
