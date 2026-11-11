package com.eudistack.ebw.keymanager.infrastructure.adapter.audit;

import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Records the key events (EUD-11 FR-04) as one structured line each, on the logger {@value #LOGGER_NAME}.
 * Every line starts with the fixed keyword {@value #AUDIT_MARK}: the platform filters the audit lines from the
 * service log by it, so no other log that merely contains the word "audit" is ingested.
 * The service output already reaches the service's log group, so no setting or infrastructure of its own
 * is needed. It is the audit trail until the events go through the audit API.
 *
 * <p>The log masking of EUD-208 does not hide the UUIDs of this logger: an audit event has to name the holder and
 * the attestation (FR-04, AC-07). A line carries the custody mode and never key material: no private key, no PRF salt, no PRF result.
 * Values come from requests, so control characters are replaced before they reach the line.</p>
 */
public class KeyAuditLogAdapter implements KeyAuditPort {

    static final String LOGGER_NAME = "audit.holder-key";

    /** Keyword at the start of every audit line; a log that is not an audit event must never carry it. */
    static final String AUDIT_MARK = "[###AUDIT###]";

    private static final Logger AUDIT_LOG = LoggerFactory.getLogger(LOGGER_NAME);
    private static final Pattern CONTROL_CHARACTERS = Pattern.compile("\\p{Cntrl}");
    private static final String UNKNOWN = "UNKNOWN";

    @Override
    public Mono<Void> emit(KeyAuditEvent event) {
        return Mono.fromRunnable(() -> {
            if (AUDIT_LOG.isInfoEnabled()) {
                AUDIT_LOG.info("{} event=HolderKeyOperation {}", AUDIT_MARK, fieldsOf(event));
            }
        });
    }

    private static String fieldsOf(KeyAuditEvent event) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("type", event.type());
        fields.put("custody_mode", event.custodyMode().getDbValue());
        fields.put("tenant", event.tenantId());
        fields.put("holder_id", event.holderId());
        fields.put("credential_id", known(event.credentialId()));
        fields.put("key_id", event.keyId());
        fields.put("jkt", known(event.jkt()));
        fields.put("algorithm", event.algorithm());
        fields.put("credential_format", event.format());
        fields.put("signing_type", event.signingType());
        fields.put("purpose", event.purpose());
        fields.put("consumer_origin", event.consumerOrigin());
        fields.put("reason", event.reason());
        fields.put("correlation_id", event.correlationId());

        StringBuilder line = new StringBuilder();
        fields.forEach((name, value) -> {
            if (value != null) {
                line.append(name).append('=')
                        .append(CONTROL_CHARACTERS.matcher(value.toString()).replaceAll("_")).append(' ');
            }
        });
        return line.toString().stripTrailing();
    }

    /** A placeholder the use case puts where the key was never resolved is not a value: it is omitted. */
    private static String known(String value) {
        return UNKNOWN.equals(value) ? null : value;
    }
}
