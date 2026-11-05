package com.eudistack.ebw.keymanager.infrastructure.adapter.audit;

import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.model.audit.AuditEventType;
import com.eudistack.ebw.domain.spi.AuditTrailPort;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sends the key events to the audit API as one {@code HolderKeyOperation} event (catalogue 2.4.0).
 *
 * <p>The tenant, actor and correlation id come from the audit context of the request, so the ones the
 * event carries are not sent. The event never carries key material. It is best effort: a broken audit
 * channel must not fail the key operation.</p>
 */
public class KeyAuditTrailAdapter implements KeyAuditPort {

    private static final String UNKNOWN = "UNKNOWN";

    private final AuditTrailPort auditTrail;

    public KeyAuditTrailAdapter(AuditTrailPort auditTrail) {
        this.auditTrail = auditTrail;
    }

    @Override
    public Mono<Void> emit(KeyAuditEvent event) {
        return Mono.defer(() -> auditTrail.stageBestEffort(entryOf(event)));
    }

    static AuditEntry entryOf(KeyAuditEvent event) {
        String resource = "holder-key:" + event.credentialId();
        Map<String, Object> details = detailsOf(event);
        String denial = denialOf(event);
        if (denial != null) {
            return AuditEntry.forReason(AuditEventType.HOLDER_KEY_OPERATION, resource, denial, details);
        }
        return AuditEntry.success(AuditEventType.HOLDER_KEY_OPERATION, resource, details);
    }

    /** The catalogue reason of an event that did not succeed, or {@code null} when it succeeded. */
    private static String denialOf(KeyAuditEvent event) {
        return switch (event.type()) {
            case SIGN_REJECTED -> rejectionReason(event.reason());
            case SIGN_TIMEOUT -> "Timeout";
            case SIGN_DEPENDENCY_FAILURE -> "DependencyUnavailable";
            case SALT_DELIVERY_DENIED -> saltReason(event.reason());
            case KEY_GENERATED, KEY_FETCHED, KEY_SIGNED, KEY_DELETED, SALT_CREATED, SALT_DELIVERED,
                 SALT_DELETED -> null;
        };
    }

    private static String rejectionReason(String reason) {
        return switch (String.valueOf(reason)) {
            case "KEY_NOT_FOUND" -> "KeyNotFound";
            case "SIGNING_TYPE_FORMAT_MISMATCH" -> "SigningTypeFormatMismatch";
            default -> "Rejected";
        };
    }

    private static String saltReason(String reason) {
        return switch (String.valueOf(reason)) {
            case "NOT_FOUND" -> "SaltNotFound";
            case "OTHER_PASSKEY" -> "SaltOtherPasskey";
            case "NO_PUBLIC_KEY" -> "SaltNoPublicKey";
            default -> "Rejected";
        };
    }

    private static String operationOf(KeyAuditEventType type) {
        return switch (type) {
            case KEY_GENERATED -> "Generate";
            case KEY_FETCHED -> "Fetch";
            case KEY_SIGNED, SIGN_REJECTED, SIGN_TIMEOUT, SIGN_DEPENDENCY_FAILURE -> "Sign";
            case KEY_DELETED -> "Delete";
            case SALT_CREATED -> "SaltCreate";
            case SALT_DELIVERED, SALT_DELIVERY_DENIED -> "SaltDeliver";
            case SALT_DELETED -> "SaltDelete";
        };
    }

    private static Map<String, Object> detailsOf(KeyAuditEvent event) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("operation", operationOf(event.type()));
        details.put("custody_mode", event.custodyMode().getDbValue());
        details.put("holder_id", event.holderId());
        details.put("credential_id", known(event.credentialId()));
        details.put("key_id", event.keyId());
        details.put("jkt", known(event.jkt()));
        details.put("algorithm", event.algorithm() == null ? null : event.algorithm().name());
        details.put("credential_format", event.format() == null ? null : event.format().name());
        details.put("signing_type", event.signingType() == null ? null : event.signingType().name());
        details.put("purpose", event.purpose() == null ? null : event.purpose().name());
        details.put("consumer_origin", event.consumerOrigin() == null ? null : event.consumerOrigin().name());
        return details;
    }

    /** A placeholder the use case puts where the key was never resolved is not a value: it is omitted. */
    private static String known(String value) {
        return UNKNOWN.equals(value) ? null : value;
    }
}
