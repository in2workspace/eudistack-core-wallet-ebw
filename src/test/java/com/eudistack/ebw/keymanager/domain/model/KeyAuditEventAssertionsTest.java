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
        KeyAuditEvent event = KeyAuditEvent.forUnwrapSignCompleted(
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
        KeyAuditEvent event = KeyAuditEvent.forUnwrapFailed(
                "sandbox",
                "holder-1",
                "cred-1",
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                "thumbprint-without-forbidden-tokens",
                Instant.now(),
                "corr-1",
                "unwrap failed: prf_salt mismatch");

        assertThatThrownBy(() -> KeyAuditEventAssertions.assertNoSensitiveData(event))
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("field 'reason'")
                .hasMessageContaining("prf");
    }
}
