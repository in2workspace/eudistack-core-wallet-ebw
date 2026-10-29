package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.ExpiredSession;
import com.eudistack.ebw.domain.model.SessionSettings;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link ExpireSessionsWorkflow}. */
@ExtendWith(MockitoExtension.class)
class ExpireSessionsWorkflowTest {

    private static final Instant STARTED_AT = Instant.parse("2026-10-15T08:00:00Z");
    private static final SessionSettings SETTINGS = new SessionSettings(Duration.ofMinutes(15), Duration.ofHours(8));

    @Mock private AuthTokenService authTokenService;
    @Mock private WalletAuthSettingsService settingsService;
    @Mock private AuditService auditService;
    @Mock private TransactionRunner transactionRunner;

    private ExpireSessionsWorkflow workflow;
    private final AtomicBoolean inTransaction = new AtomicBoolean();

    @BeforeEach
    void setUp() {
        workflow = new ExpireSessionsWorkflow(authTokenService, settingsService, auditService, transactionRunner);
    }

    private void runTransactionsInline() {
        when(transactionRunner.inTransaction(any())).thenAnswer(inv -> {
            inTransaction.set(true);
            return inv.getArgument(0);
        });
    }

    @Test
    void expireLapsedSessions_idleAndMaxDurationSessions_auditsEachWithTheLimitItReached() {
        // Arrange
        var userId = UUID.randomUUID();
        var idle = new ExpiredSession(UUID.randomUUID(), userId, STARTED_AT, STARTED_AT.plus(Duration.ofHours(1)));
        var max = new ExpiredSession(UUID.randomUUID(), userId, STARTED_AT, STARTED_AT.plus(Duration.ofHours(8)));
        when(settingsService.session()).thenReturn(Mono.just(SETTINGS));
        when(authTokenService.expireLapsedSessions()).thenReturn(Flux.just(idle, max));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        runTransactionsInline();

        // Act
        StepVerifier.create(workflow.expireLapsedSessions()).expectNext(2L).verifyComplete();

        // Assert
        assertThat(inTransaction).isTrue();
        verify(auditService).record("session", idle.sessionId(), AuthAuditEvents.SESSION_EXPIRED, userId,
                Map.of("reason", "idle_timeout"));
        verify(auditService).record("session", max.sessionId(), AuthAuditEvents.SESSION_EXPIRED, userId,
                Map.of("reason", "max_duration"));
    }

    @Test
    void expireLapsedSessions_noLapsedSession_auditsNothing() {
        // Arrange
        when(settingsService.session()).thenReturn(Mono.just(SETTINGS));
        when(authTokenService.expireLapsedSessions()).thenReturn(Flux.empty());
        runTransactionsInline();

        // Act + Assert
        StepVerifier.create(workflow.expireLapsedSessions()).expectNext(0L).verifyComplete();
        verify(auditService, never()).record(any(), any(), any(), any(), any());
    }

    @Test
    void expireLapsedSessions_settingsUnavailable_closesNothing() {
        // Arrange
        when(settingsService.session()).thenReturn(Mono.error(new IllegalStateException("db down")));

        // Act + Assert
        StepVerifier.create(workflow.expireLapsedSessions()).expectError(IllegalStateException.class).verify();
        verify(authTokenService, never()).expireLapsedSessions();
    }
}
