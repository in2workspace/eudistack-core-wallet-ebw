package com.eudistack.ebw.keymanager.domain.model;

import java.lang.reflect.RecordComponent;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Shared assertion for CA-1 (audit events must never leak PRF salt, wrap key, or other
 * sensitive material) — reused across every use case that emits a {@link KeyAuditEvent}.
 */
public final class KeyAuditEventAssertions {

    private static final List<String> FORBIDDEN_TERMS =
            List.of("prf", "wrapkey", "salt", "privatekey", "email", "deviceid");

    private KeyAuditEventAssertions() {
    }

    public static void assertNoSensitiveData(KeyAuditEvent event) {
        for (RecordComponent component : KeyAuditEvent.class.getRecordComponents()) {
            Object value;
            try {
                value = component.getAccessor().invoke(event);
            } catch (ReflectiveOperationException e) {
                throw new AssertionError("Failed to inspect KeyAuditEvent record components", e);
            }
            if (value instanceof String str) {
                String lower = str.toLowerCase();
                for (String term : FORBIDDEN_TERMS) {
                    assertThat(lower)
                            .as("CA-1: field '%s' must not contain sensitive term '%s'",
                                    component.getName(), term)
                            .doesNotContain(term);
                }
            }
        }
    }
}
