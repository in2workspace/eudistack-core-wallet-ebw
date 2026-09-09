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

    /**
     * RFC 7638 JWK thumbprints are SHA-256 encoded as base64url. Any 3–4 letter token
     * ({@code prf}, {@code salt}, …) can appear as a coincidental substring of a real
     * thumbprint and is not a leak of key material.
     */
    private static final List<String> HASH_FIELDS = List.of("jkt");

    private KeyAuditEventAssertions() {
    }

    public static void assertNoSensitiveData(KeyAuditEvent event) {
        for (RecordComponent component : KeyAuditEvent.class.getRecordComponents()) {
            if (HASH_FIELDS.contains(component.getName())) {
                continue;
            }
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
