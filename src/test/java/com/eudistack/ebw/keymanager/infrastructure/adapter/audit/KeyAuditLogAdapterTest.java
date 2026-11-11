package com.eudistack.ebw.keymanager.infrastructure.adapter.audit;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.eudistack.ebw.infrastructure.configuration.logging.MaskingPatternLayout;
import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.model.SignaturePurpose;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import reactor.test.StepVerifier;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class KeyAuditLogAdapterTest {

    private static final Instant NOW = Instant.parse("2026-11-05T10:00:00Z");

    private final KeyAuditLogAdapter adapter = new KeyAuditLogAdapter();
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private Logger logger;

    @BeforeEach
    void attachAppender() {
        logger = (Logger) LoggerFactory.getLogger(KeyAuditLogAdapter.LOGGER_NAME);
        logger.setLevel(Level.INFO);
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(appender);
    }

    @Test
    void signature_isOneLineWithTheCustodyModeAndTheSigningContext() {
        emit(KeyAuditEvent.forSigning(KeyAuditEventType.KEY_SIGNED, "sandbox", "holder-1", "cred-1",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256, "jkt-1", NOW, "corr-1",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.OID4VP_RESPONDER, null, "key-1"));

        assertThat(onlyLine())
                .startsWith("[###AUDIT###] event=HolderKeyOperation type=KEY_SIGNED custody_mode=server tenant=sandbox")
                .contains("holder_id=holder-1", "credential_id=cred-1", "key_id=key-1", "jkt=jkt-1",
                        "signing_type=KB_JWT", "correlation_id=corr-1")
                .doesNotContain("reason=");
    }

    @Test
    void saltDenial_carriesThePasskeyCustodyAndTheReason() {
        emit(KeyAuditEvent.forSalt(KeyAuditEventType.SALT_DELIVERY_DENIED, "sandbox", "holder-1", "cred-1",
                "OTHER_PASSKEY", NOW, "corr-1"));

        assertThat(onlyLine())
                .contains("type=SALT_DELIVERY_DENIED", "custody_mode=passkey", "reason=OTHER_PASSKEY")
                .doesNotContain("jkt=", "key_id=");
    }

    @Test
    void unresolvedKeyPlaceholders_areOmitted() {
        emit(KeyAuditEvent.forSigning(KeyAuditEventType.SIGN_TIMEOUT, "sandbox", "holder-1", "UNKNOWN",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256, "UNKNOWN", NOW, "corr-1",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.OID4VP_RESPONDER,
                "TIMEOUT", null));

        assertThat(onlyLine()).doesNotContain("credential_id=", "jkt=").contains("reason=TIMEOUT");
    }

    @Test
    void controlCharactersFromARequest_cannotBreakTheLine() {
        emit(KeyAuditEvent.forKeyDeleted("sandbox", "holder-1", "cred\n2026-01-01 forged=1", "key-1", NOW, "corr-1"));

        assertThat(onlyLine()).doesNotContain("\n").contains("credential_id=cred_2026-01-01 forged=1");
    }

    @Test
    void lineAsPrintedAfterTheMasking_stillNamesTheHolderTheAttestationAndTheKey() {
        String holder = "550e8400-e29b-41d4-a716-446655440000";
        emit(KeyAuditEvent.forSigning(KeyAuditEventType.KEY_SIGNED, "sandbox", holder, "cred-1",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", NOW, "corr-1",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.OID4VP_RESPONDER, null,
                "9b2f7c1e-3a4d-4e5f-8a6b-7c8d9e0f1a2b"));

        // The service log goes through the masking of EUD-208 before it leaves the service: that is the line
        // the platform filter receives, not the one the adapter formats.
        MaskingPatternLayout layout = new MaskingPatternLayout();
        layout.setContext(new LoggerContext());
        layout.setPattern("%msg");
        layout.start();
        String printed = layout.doLayout(appender.list.getFirst());

        assertThat(printed)
                .startsWith("[###AUDIT###] event=HolderKeyOperation")
                .contains("holder_id=" + holder, "key_id=9b2f7c1e-3a4d-4e5f-8a6b-7c8d9e0f1a2b",
                        "jkt=NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    private void emit(KeyAuditEvent event) {
        StepVerifier.create(adapter.emit(event)).verifyComplete();
    }

    private String onlyLine() {
        assertThat(appender.list).hasSize(1);
        return appender.list.getFirst().getFormattedMessage();
    }
}
