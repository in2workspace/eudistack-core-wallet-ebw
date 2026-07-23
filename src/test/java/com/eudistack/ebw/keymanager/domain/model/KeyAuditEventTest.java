package com.eudistack.ebw.keymanager.domain.model;

import com.eudistack.ebw.keymanager.domain.exception.KeyAuditEventValidationException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for the {@link KeyAuditEvent} compact constructor validation and factory methods.
 *
 * <p>Spec: ADR-062, ADR-069, FR-61, EUDISTACK-119 AD-119-3, EUDISTACK-407 AC-08.</p>
 */
class KeyAuditEventTest {

    private static final String TENANT = "tenant-1";
    private static final String HOLDER = "holder-1";
    private static final String CRED_ID = "cred-1";
    private static final CredentialFormat FORMAT = CredentialFormat.SD_JWT_VC;
    private static final KeyAlgorithm ALGORITHM = KeyAlgorithm.ES256;
    private static final String JKT = "jkt-thumbprint";
    private static final Instant TIMESTAMP = Instant.now();
    private static final String CORRELATION_ID = "corr-1";

    private static KeyAuditEvent fullEvent(KeyAuditEvent.KeyAuditEventType type,
                                            String tenantId, String holderId,
                                            String credentialId, CredentialFormat format,
                                            KeyAlgorithm algorithm, String jkt,
                                            Instant timestamp, String correlationId) {
        return new KeyAuditEvent(
                type, tenantId, holderId, credentialId, format, algorithm, jkt,
                timestamp, correlationId,
                null, null, null, null, null);
    }

    // ------------------------------------------------------------------ fields required for every event type

    @Nested
    class RequiredForEveryEventType {

        @Test
        void constructor_nullType_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(null, TENANT, HOLDER, CRED_ID, FORMAT, ALGORITHM,
                    JKT, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("type");
        }

        @Test
        void constructor_nullTenantId_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_GENERATED, null,
                    HOLDER, CRED_ID, FORMAT, ALGORITHM, JKT, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("tenantId");
        }

        @Test
        void constructor_blankTenantId_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_GENERATED, "  ",
                    HOLDER, CRED_ID, FORMAT, ALGORITHM, JKT, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("tenantId");
        }

        @Test
        void constructor_nullHolderId_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_GENERATED, TENANT,
                    null, CRED_ID, FORMAT, ALGORITHM, JKT, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("holderId");
        }

        @Test
        void constructor_blankHolderId_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_GENERATED, TENANT,
                    "  ", CRED_ID, FORMAT, ALGORITHM, JKT, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("holderId");
        }

        @Test
        void constructor_nullTimestamp_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_GENERATED, TENANT,
                    HOLDER, CRED_ID, FORMAT, ALGORITHM, JKT, null, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("timestamp");
        }

        @Test
        void constructor_nullCorrelationId_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_GENERATED, TENANT,
                    HOLDER, CRED_ID, FORMAT, ALGORITHM, JKT, TIMESTAMP, null))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("correlationId");
        }

        @Test
        void constructor_blankCorrelationId_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_GENERATED, TENANT,
                    HOLDER, CRED_ID, FORMAT, ALGORITHM, JKT, TIMESTAMP, "  "))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("correlationId");
        }
    }

    // ------------------------------------------------------------------ key-context events (US-02/US-03/US-04)

    @Nested
    class KeyContextRequiredEvents {

        @Test
        void constructor_nullCredentialId_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_GENERATED, TENANT,
                    HOLDER, null, FORMAT, ALGORITHM, JKT, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("credentialId");
        }

        @Test
        void constructor_blankCredentialId_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_FETCHED, TENANT,
                    HOLDER, "  ", FORMAT, ALGORITHM, JKT, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("credentialId");
        }

        @Test
        void constructor_nullFormat_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.KEY_SIGNED, TENANT,
                    HOLDER, CRED_ID, null, ALGORITHM, JKT, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("format");
        }

        @Test
        void constructor_nullAlgorithm_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.SIGN_REJECTED, TENANT,
                    HOLDER, CRED_ID, FORMAT, null, JKT, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("algorithm");
        }

        @Test
        void constructor_nullJkt_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.UNWRAP_SIGN_COMPLETED,
                    TENANT, HOLDER, CRED_ID, FORMAT, ALGORITHM, null, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("jkt");
        }

        @Test
        void constructor_blankJkt_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.SIGN_TIMEOUT, TENANT,
                    HOLDER, CRED_ID, FORMAT, ALGORITHM, "  ", TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("jkt");
        }

        @Test
        void constructor_allFieldsPopulated_constructsSuccessfully() {
            KeyAuditEvent event = fullEvent(KeyAuditEvent.KeyAuditEventType.SIGN_DEPENDENCY_FAILURE,
                    TENANT, HOLDER, CRED_ID, FORMAT, ALGORITHM, JKT, TIMESTAMP, CORRELATION_ID);

            assertThat(event.credentialId()).isEqualTo(CRED_ID);
            assertThat(event.format()).isEqualTo(FORMAT);
            assertThat(event.algorithm()).isEqualTo(ALGORITHM);
            assertThat(event.jkt()).isEqualTo(JKT);
        }
    }

    // ------------------------------------------------------------------ no-key-context events (US-06/US-08)

    @Nested
    class NoKeyContextEvents {

        @Test
        void forConsent_givenValidArgs_constructsWithNullKeyFields() {
            KeyAuditEvent event = KeyAuditEvent.forConsent(TENANT, HOLDER, TIMESTAMP, CORRELATION_ID);

            assertThat(event.type()).isEqualTo(KeyAuditEvent.KeyAuditEventType.CONSTRAINT_ACCEPTED);
            assertThat(event.credentialId()).isNull();
            assertThat(event.format()).isNull();
            assertThat(event.algorithm()).isNull();
            assertThat(event.jkt()).isNull();
        }

        @Test
        void forPrfUnsupported_givenValidArgs_constructsWithNullKeyFields() {
            KeyAuditEvent event = KeyAuditEvent.forPrfUnsupported(TENANT, HOLDER, TIMESTAMP, CORRELATION_ID);

            assertThat(event.type()).isEqualTo(KeyAuditEvent.KeyAuditEventType.ONBOARDING_BLOCKED_PRF_UNSUPPORTED);
            assertThat(event.credentialId()).isNull();
            assertThat(event.format()).isNull();
            assertThat(event.algorithm()).isNull();
            assertThat(event.jkt()).isNull();
        }
    }

    // ------------------------------------------------------------------ wrap-context events (US-08)

    @Nested
    class WrapContextEvent {

        @Test
        void forWrap_givenValidArgs_constructsWithNullFormatAlgorithmJkt() {
            KeyAuditEvent event = KeyAuditEvent.forWrap(TENANT, HOLDER, CRED_ID, TIMESTAMP, CORRELATION_ID);

            assertThat(event.type()).isEqualTo(KeyAuditEvent.KeyAuditEventType.WRAP_COMPLETED);
            assertThat(event.credentialId()).isEqualTo(CRED_ID);
            assertThat(event.format()).isNull();
            assertThat(event.algorithm()).isNull();
            assertThat(event.jkt()).isNull();
        }

        @Test
        void constructor_wrapCompletedWithNullCredentialId_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.WRAP_COMPLETED, TENANT,
                    HOLDER, null, null, null, null, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("credentialId");
        }
    }

    // ------------------------------------------------------------------ unwrap-failed events (US-04/US-08)

    @Nested
    class UnwrapFailedContextEvent {

        @Test
        void forUnwrapFailed_givenNullJkt_constructsSuccessfully() {
            KeyAuditEvent event = KeyAuditEvent.forUnwrapFailed(TENANT, HOLDER, CRED_ID, FORMAT,
                    ALGORITHM, null, TIMESTAMP, CORRELATION_ID, "signature_invalid");

            assertThat(event.type()).isEqualTo(KeyAuditEvent.KeyAuditEventType.UNWRAP_FAILED);
            assertThat(event.jkt()).isNull();
            assertThat(event.reason()).isEqualTo("signature_invalid");
        }

        @Test
        void constructor_unwrapFailedWithNullFormat_throwsKeyAuditEventValidationException() {
            assertThatThrownBy(() -> fullEvent(KeyAuditEvent.KeyAuditEventType.UNWRAP_FAILED, TENANT,
                    HOLDER, CRED_ID, null, ALGORITHM, null, TIMESTAMP, CORRELATION_ID))
                    .isInstanceOf(KeyAuditEventValidationException.class)
                    .hasMessageContaining("format");
        }
    }

    // ------------------------------------------------------------------ signing events (US-03)

    @Nested
    class SigningFactory {

        @Test
        void forSigning_givenValidArgs_populatesOptionalSigningFields() {
            KeyAuditEvent event = KeyAuditEvent.forSigning(
                    KeyAuditEvent.KeyAuditEventType.KEY_SIGNED,
                    TENANT, HOLDER, CRED_ID, FORMAT, ALGORITHM, JKT, TIMESTAMP, CORRELATION_ID,
                    SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM,
                    null, "key-id-1");

            assertThat(event.signingType()).isEqualTo(SigningType.KB_JWT);
            assertThat(event.purpose()).isEqualTo(SignaturePurpose.PRESENTATION);
            assertThat(event.consumerOrigin()).isEqualTo(ConsumerOrigin.SYSTEM);
            assertThat(event.keyId()).isEqualTo("key-id-1");
        }
    }
}
