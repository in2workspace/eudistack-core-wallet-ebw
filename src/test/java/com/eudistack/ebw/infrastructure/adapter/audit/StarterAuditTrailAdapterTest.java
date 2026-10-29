package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.auditoria.application.ReactiveAuditPublisher;
import com.eudistack.auditoria.domain.AuditDraft;
import com.eudistack.auditoria.domain.AuditResult;
import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.model.audit.AuditEventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.ReactiveTransaction;
import org.springframework.transaction.ReactiveTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StarterAuditTrailAdapterTest {

    private final ReactiveAuditPublisher publisher = mock(ReactiveAuditPublisher.class);
    private final ReactiveTransactionManager transactionManager = mock(ReactiveTransactionManager.class);
    private StarterAuditTrailAdapter adapter;

    @BeforeEach
    void setUp() {
        ReactiveTransaction transaction = mock(ReactiveTransaction.class);
        when(transactionManager.getReactiveTransaction(any())).thenReturn(Mono.just(transaction));
        when(transactionManager.commit(transaction)).thenReturn(Mono.empty());
        when(publisher.stage(any())).thenReturn(Mono.empty());
        adapter = new StarterAuditTrailAdapter(publisher, transactionManager);
    }

    @Test
    void stageInNewTransaction_successEntry_handsTheFactToThePublisherAsSuccess() {
        // Arrange
        AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, "external-system:smtp",
                Map.of("system", "smtp"));

        // Act
        StepVerifier.create(adapter.stageInNewTransaction(entry)).verifyComplete();

        // Assert
        ArgumentCaptor<AuditDraft> draft = ArgumentCaptor.forClass(AuditDraft.class);
        verify(publisher).stage(draft.capture());
        assertEquals(AuditResult.SUCCESS, draft.getValue().result());
        assertNull(draft.getValue().reason());
        assertEquals("ExternalSystemAccess", draft.getValue().fact().eventType());
        assertEquals("AccessExternalSystem", draft.getValue().fact().action());
        assertEquals("external-system:smtp", draft.getValue().fact().resource());
        assertEquals("wallet-ebw", draft.getValue().fact().source());
        assertEquals(Map.of("system", "smtp"), draft.getValue().fact().details());
    }

    @Test
    void stageInNewTransaction_failureEntry_keepsTheReason() {
        // Arrange
        AuditEntry entry = AuditEntry.forReason(AuditEventType.EXTERNAL_SYSTEM_ACCESS, "external-system:smtp",
                "Unreachable", Map.of());

        // Act
        StepVerifier.create(adapter.stageInNewTransaction(entry)).verifyComplete();

        // Assert
        ArgumentCaptor<AuditDraft> draft = ArgumentCaptor.forClass(AuditDraft.class);
        verify(publisher).stage(draft.capture());
        assertEquals(AuditResult.FAILURE, draft.getValue().result());
        assertEquals("Unreachable", draft.getValue().reason());
    }

    @Test
    void stageInNewTransaction_entry_opensATransactionOfItsOwn() {
        // Arrange
        AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, "external-system:smtp", Map.of());

        // Act
        StepVerifier.create(adapter.stageInNewTransaction(entry)).verifyComplete();

        // Assert
        ArgumentCaptor<TransactionDefinition> definition = ArgumentCaptor.forClass(TransactionDefinition.class);
        verify(transactionManager).getReactiveTransaction(definition.capture());
        assertEquals(TransactionDefinition.PROPAGATION_REQUIRES_NEW, definition.getValue().getPropagationBehavior());
    }

    @Test
    void stageBestEffort_publisherFails_doesNotFailTheCaller() {
        // Arrange
        when(publisher.stage(any())).thenReturn(Mono.error(new IllegalStateException("audit down")));
        AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, "external-system:smtp", Map.of());

        // Act & Assert
        StepVerifier.create(adapter.stageBestEffort(entry)).verifyComplete();
    }
}
