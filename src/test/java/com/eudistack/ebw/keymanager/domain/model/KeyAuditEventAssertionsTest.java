package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Guards CA-1 against false positives on RFC 7638 thumbprints, which are high-entropy
 * base64url hashes and may coincidentally contain short tokens such as {@code prf}.
 */
class KeyAuditEventAssertionsTest {

    @Test
    void assertNoSensitiveData_jktContainingPrfSubstring_doesNotFail() {
        KeyAuditEvent event = KeyAuditEvent.forGeneration(
                KeyAuditEvent.KeyAuditEventType.KEY_GENERATED,
                "sandbox",
                "holder-1",
                "cred-1",
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                "nX9prfK2saltQ8wrapkey",
                Instant.now(),
                "corr-1");

        KeyAuditEventAssertions.assertNoSensitiveData(event);
    }

    @Test
    void assertNoSensitiveData_reasonContainingPrf_fails() {
        KeyAuditEvent event = KeyAuditEvent.forSalt(
                KeyAuditEvent.KeyAuditEventType.SALT_DELIVERY_DENIED,
                "sandbox",
                "holder-1",
                "cred-1",
                "denied: prf_salt mismatch",
                Instant.now(),
                "corr-1");

        assertThatThrownBy(() -> KeyAuditEventAssertions.assertNoSensitiveData(event))
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("field 'reason'")
                .hasMessageContaining("prf");
    }
}
