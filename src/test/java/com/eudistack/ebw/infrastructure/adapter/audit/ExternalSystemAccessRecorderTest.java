package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.model.audit.AuditEventType;
import com.eudistack.ebw.domain.model.audit.AuditResult;
import com.eudistack.ebw.domain.model.audit.ExternalSystemTarget;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.ConnectException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExternalSystemAccessRecorderTest {

    private static final ExternalSystemTarget TARGET =
            ExternalSystemTarget.mailProvider("smtp.example.com", ExternalSystemTarget.AUTHENTICATION_BASIC);

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private final ExternalSystemAccessRecorder recorder = new ExternalSystemAccessRecorder(auditTrail);

    @Test
    void record_callSucceeds_stagesSuccessWithTheTargetAndReturnsTheValue() {
        // Arrange
        Mono<String> call = Mono.just("sent");

        // Act & Assert
        StepVerifier.create(recorder.record(TARGET, "verification-code-email", call))
                .expectNext("sent")
                .verifyComplete();
        AuditEntry entry = auditTrail.staged().getFirst();
        assertEquals(AuditEventType.EXTERNAL_SYSTEM_ACCESS, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("external-system:smtp.example.com", entry.resource());
        assertEquals("MailProvider", entry.details().get("system_type"));
        assertEquals("smtp.example.com", entry.details().get("system"));
        assertEquals("verification-code-email", entry.details().get("operation"));
        assertEquals("Basic", entry.details().get("authentication_method"));
    }

    @Test
    void record_callCompletesEmpty_stagesSuccessAndStaysEmpty() {
        // Arrange
        Mono<Void> call = Mono.empty();

        // Act & Assert
        StepVerifier.create(recorder.record(TARGET, "verification-code-email", call)).verifyComplete();
        assertEquals(AuditResult.SUCCESS, auditTrail.staged().getFirst().result());
    }

    @Test
    void record_callFails_stagesTheClassifiedReasonAndPropagatesTheError() {
        // Arrange
        ConnectException error = new ConnectException("refused");

        // Act & Assert
        StepVerifier.create(recorder.record(TARGET, "verification-code-email", Mono.error(error)))
                .expectErrorMatches(propagated -> propagated == error)
                .verify();
        AuditEntry entry = auditTrail.staged().getFirst();
        assertEquals(AuditResult.FAILURE, entry.result());
        assertEquals("Unreachable", entry.reason());
    }

    @Test
    void record_auditChannelDown_stillReturnsTheValueOfTheCall() {
        // Arrange
        ExternalSystemAccessRecorder brokenRecorder = new ExternalSystemAccessRecorder(new RecordingAuditTrail().failing());

        // Act & Assert
        StepVerifier.create(brokenRecorder.record(TARGET, "verification-code-email", Mono.just("sent")))
                .expectNext("sent")
                .verifyComplete();
    }

    @Test
    void record_auditChannelDownAndCallFails_propagatesTheOriginalError() {
        // Arrange
        ExternalSystemAccessRecorder brokenRecorder = new ExternalSystemAccessRecorder(new RecordingAuditTrail().failing());
        IllegalStateException error = new IllegalStateException("smtp down");

        // Act & Assert
        StepVerifier.create(brokenRecorder.record(TARGET, "verification-code-email", Mono.error(error)))
                .expectErrorMatches(propagated -> propagated == error)
                .verify();
        assertTrue(auditTrail.staged().isEmpty());
    }
}
