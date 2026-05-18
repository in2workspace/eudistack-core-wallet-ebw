package com.eudistack.ebw.wallet.config.application.operational;

import com.eudistack.ebw.wallet.config.application.operational.exception.ProbeFailedException;
import com.eudistack.ebw.wallet.config.application.operational.exception.UnsupportedKeyManagerException;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.ActivationStatus;
import com.eudistack.ebw.wallet.config.domain.model.operational.DbTdeOperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalAuditEvent;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult;
import com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort;
import com.eudistack.ebw.wallet.config.domain.port.OperationalConfigAuditPort;
import com.eudistack.ebw.wallet.config.domain.port.OperationalConfigPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.transaction.ReactiveTransaction;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OperationalConfigWriter}.
 *
 * <p>Covers T-2 (happy path — validate → probe → upsert → audit PERMIT) and T-3 (negative
 * scenarios — unsupported key_manager, probe Failed/NotRegistered, optimistic-lock rethrow)
 * from tech-design §2.3 (EUDISTACK-414).
 *
 * <p>No Spring context. Ports are mocked with Mockito. {@link TransactionalOperator} is mocked
 * to execute the lambda inline (pass-through) so that the test does not require a real R2DBC
 * connection or a running transaction manager.
 */
class OperationalConfigWriterServiceTest {

    private static final String VALID_ARN = "arn:aws:kms:eu-west-1:123456789012:key/mrk-abc123";
    private static final byte[] VALID_DEK = new byte[]{0x01, 0x02, 0x03};
    private static final String ACTOR = "test-actor@example.com";
    private static final String CORRELATION_ID = "corr-001";

    private OperationalConfigPort operationalConfigPort;
    private OperationalConfigAuditPort auditPort;
    private KeyManagerConnectivityPort connectivityPort;
    private TransactionalOperator transactionalOperator;
    private OperationalConfigWriter writer;

    @BeforeEach
    void setUp() {
        operationalConfigPort = mock(OperationalConfigPort.class);
        auditPort = mock(OperationalConfigAuditPort.class);
        connectivityPort = mock(KeyManagerConnectivityPort.class);
        transactionalOperator = mock(TransactionalOperator.class);

        // Stub auditPort: both recordPermit and recordDeny complete empty (no I/O)
        when(auditPort.recordPermit(any())).thenReturn(Mono.empty());
        when(auditPort.recordDeny(any())).thenReturn(Mono.empty());

        // Stub TransactionalOperator: execute the lambda inline (pass-through, no real tx).
        // doInTransaction returns Publisher<T>; wrapping with Flux.from satisfies the Flux<T>
        // return type of TransactionalOperator.execute.
        ReactiveTransaction fakeTx = mock(ReactiveTransaction.class);
        when(transactionalOperator.execute(any())).thenAnswer(invocation -> {
            org.springframework.transaction.reactive.TransactionCallback<?> callback =
                    invocation.getArgument(0);
            return Flux.from(callback.doInTransaction(fakeTx));
        });

        writer = new OperationalConfigWriter(
                operationalConfigPort, auditPort, connectivityPort, transactionalOperator);
    }

    // ------------------------------------------------------------------
    // T-2: happy path — POST (version 0) with DB_TDE
    // ------------------------------------------------------------------

    /**
     * Happy path: valid {@code DB_TDE} command. Verifies that the writer calls the probe once,
     * the upsert once, and emits a PERMIT audit ({@code CONFIG_APPLIED}) exactly once.
     * {@code recordDeny} must never be called.
     */
    @Test
    void apply_validDbTdeCommand_executesProbeThenUpsertThenPermitAudit() {
        // Given
        DbTdeOperationalConfig config =
                new DbTdeOperationalConfig(VALID_ARN, VALID_DEK, "AES-256-GCM");
        ApplyOperationalConfigCommand command = new ApplyOperationalConfigCommand(
                KeyManager.DB_TDE, config, ACTOR, CORRELATION_ID, Optional.empty());

        OperationalConfigDescriptor persisted = buildDescriptor(config, 0L);

        when(connectivityPort.probe(KeyManager.DB_TDE, config))
                .thenReturn(Mono.just(new ProbeResult.Ok(42L)));
        when(operationalConfigPort.upsert(any())).thenReturn(Mono.just(persisted));

        // When
        Mono<OperationalConfigDescriptor> result = writer.apply(command);

        // Then — descriptor with ACTIVE status is emitted
        StepVerifier.create(result)
                .assertNext(d -> assertThat(d.activationStatus()).isEqualTo(ActivationStatus.ACTIVE))
                .verifyComplete();

        // Verify interaction order: probe once, upsert once, PERMIT audit once, DENY never
        verify(connectivityPort).probe(KeyManager.DB_TDE, config);
        verify(operationalConfigPort).upsert(any());
        verify(auditPort).recordPermit(any());
        verify(auditPort, never()).recordDeny(any());
    }

    // ------------------------------------------------------------------
    // T-3: unsupported key_manager → CONFIG_REJECTED DENY, no probe
    // ------------------------------------------------------------------

    /**
     * When {@code key_manager=HSM} is supplied, the writer rejects it inside
     * {@code Mono.fromCallable} with {@link UnsupportedKeyManagerException}. The
     * {@code onErrorResume} handler must catch it, emit a DENY audit
     * ({@code CONFIG_REJECTED}), and re-signal the exception.
     *
     * <p>This is the critical regression test for the Task 3 fix-up: the exception must be
     * wrapped in {@code Mono.fromCallable} so that {@code onErrorResume} can intercept it.
     * Probe and upsert must never be called.
     */
    @Test
    void apply_unsupportedKeyManager_emitsConfigRejectedDenyAndThrows() {
        // Given — HSM is not supported in US-03 (AD-S1)
        DbTdeOperationalConfig config =
                new DbTdeOperationalConfig(VALID_ARN, VALID_DEK, "AES-256-GCM");
        ApplyOperationalConfigCommand command = new ApplyOperationalConfigCommand(
                KeyManager.HSM, config, ACTOR, CORRELATION_ID, Optional.empty());

        // When
        Mono<OperationalConfigDescriptor> result = writer.apply(command);

        // Then — UnsupportedKeyManagerException propagates
        StepVerifier.create(result)
                .expectError(UnsupportedKeyManagerException.class)
                .verify();

        // DENY audit emitted once with CONFIG_REJECTED
        ArgumentCaptor<OperationalAuditEvent> denyCaptor =
                ArgumentCaptor.forClass(OperationalAuditEvent.class);
        verify(auditPort).recordDeny(denyCaptor.capture());
        assertThat(denyCaptor.getValue().outcome()).isEqualTo(OperationalAuditEvent.Outcome.DENY);
        assertThat(denyCaptor.getValue().event())
                .isEqualTo(OperationalAuditEvent.EventType.CONFIG_REJECTED);

        // Probe and upsert must never be called
        verify(connectivityPort, never()).probe(any(), any());
        verify(operationalConfigPort, never()).upsert(any());
        verify(auditPort, never()).recordPermit(any());
    }

    // ------------------------------------------------------------------
    // T-3: probe returns Failed → CONNECTIVITY_FAILED DENY + ProbeFailedException
    // ------------------------------------------------------------------

    /**
     * When the connectivity probe returns {@link ProbeResult.Failed}, the writer must emit a
     * DENY audit ({@code CONNECTIVITY_FAILED}) and throw {@link ProbeFailedException}.
     * The upsert must never be called. DENY must be emitted exactly once (not twice).
     */
    @Test
    void apply_probeReturnsFailedResult_emitsConnectivityFailedDenyAndThrows() {
        // Given
        DbTdeOperationalConfig config =
                new DbTdeOperationalConfig(VALID_ARN, VALID_DEK, "AES-256-GCM");
        ApplyOperationalConfigCommand command = new ApplyOperationalConfigCommand(
                KeyManager.DB_TDE, config, ACTOR, CORRELATION_ID, Optional.empty());

        when(connectivityPort.probe(KeyManager.DB_TDE, config))
                .thenReturn(Mono.just(new ProbeResult.Failed("KMS unreachable")));

        // When
        Mono<OperationalConfigDescriptor> result = writer.apply(command);

        // Then — ProbeFailedException propagates
        StepVerifier.create(result)
                .expectError(ProbeFailedException.class)
                .verify();

        // DENY audit emitted exactly once — not twice (no double-audit via onErrorResume)
        ArgumentCaptor<OperationalAuditEvent> denyCaptor =
                ArgumentCaptor.forClass(OperationalAuditEvent.class);
        verify(auditPort).recordDeny(denyCaptor.capture());
        assertThat(denyCaptor.getValue().outcome()).isEqualTo(OperationalAuditEvent.Outcome.DENY);
        assertThat(denyCaptor.getValue().event())
                .isEqualTo(OperationalAuditEvent.EventType.CONNECTIVITY_FAILED);

        // Upsert and PERMIT must never be called
        verify(operationalConfigPort, never()).upsert(any());
        verify(auditPort, never()).recordPermit(any());
    }

    // ------------------------------------------------------------------
    // T-3: probe returns NotRegistered → CONNECTIVITY_FAILED DENY + ProbeFailedException
    // ------------------------------------------------------------------

    /**
     * When the connectivity probe returns {@link ProbeResult.NotRegistered} (safety-net path
     * per AD-S1), the writer must emit a DENY audit ({@code CONNECTIVITY_FAILED}) and throw
     * {@link ProbeFailedException}. Same single-DENY contract as the {@code Failed} case.
     */
    @Test
    void apply_probeReturnsNotRegistered_emitsConnectivityFailedDenyAndThrows() {
        // Given
        DbTdeOperationalConfig config =
                new DbTdeOperationalConfig(VALID_ARN, VALID_DEK, "AES-256-GCM");
        ApplyOperationalConfigCommand command = new ApplyOperationalConfigCommand(
                KeyManager.DB_TDE, config, ACTOR, CORRELATION_ID, Optional.empty());

        when(connectivityPort.probe(KeyManager.DB_TDE, config))
                .thenReturn(Mono.just(new ProbeResult.NotRegistered()));

        // When
        Mono<OperationalConfigDescriptor> result = writer.apply(command);

        // Then — ProbeFailedException propagates
        StepVerifier.create(result)
                .expectError(ProbeFailedException.class)
                .verify();

        // DENY audit emitted exactly once
        ArgumentCaptor<OperationalAuditEvent> denyCaptor =
                ArgumentCaptor.forClass(OperationalAuditEvent.class);
        verify(auditPort).recordDeny(denyCaptor.capture());
        assertThat(denyCaptor.getValue().outcome()).isEqualTo(OperationalAuditEvent.Outcome.DENY);
        assertThat(denyCaptor.getValue().event())
                .isEqualTo(OperationalAuditEvent.EventType.CONNECTIVITY_FAILED);

        verify(operationalConfigPort, never()).upsert(any());
        verify(auditPort, never()).recordPermit(any());
    }

    // ------------------------------------------------------------------
    // T-3: upsert throws OptimisticLockingFailureException → DENY + rethrow
    // ------------------------------------------------------------------

    /**
     * When {@link OperationalConfigPort#upsert} returns a {@code Mono.error} wrapping an
     * {@link OptimisticLockingFailureException}, the writer must emit a DENY audit
     * ({@code CONFIG_REJECTED}) and re-signal the same exception.
     */
    @Test
    void apply_upsertThrowsOptimisticLockException_emitsDenyAndRethrows() {
        // Given
        DbTdeOperationalConfig config =
                new DbTdeOperationalConfig(VALID_ARN, VALID_DEK, "AES-256-GCM");
        ApplyOperationalConfigCommand command = new ApplyOperationalConfigCommand(
                KeyManager.DB_TDE, config, ACTOR, CORRELATION_ID, Optional.of(2L));

        when(connectivityPort.probe(KeyManager.DB_TDE, config))
                .thenReturn(Mono.just(new ProbeResult.Ok(10L)));
        when(operationalConfigPort.upsert(any()))
                .thenReturn(Mono.error(
                        new OptimisticLockingFailureException("version mismatch: expected 2")));

        // When
        Mono<OperationalConfigDescriptor> result = writer.apply(command);

        // Then — OptimisticLockingFailureException re-propagates
        StepVerifier.create(result)
                .expectError(OptimisticLockingFailureException.class)
                .verify();

        // DENY audit emitted once with CONFIG_REJECTED
        ArgumentCaptor<OperationalAuditEvent> denyCaptor =
                ArgumentCaptor.forClass(OperationalAuditEvent.class);
        verify(auditPort).recordDeny(denyCaptor.capture());
        assertThat(denyCaptor.getValue().outcome()).isEqualTo(OperationalAuditEvent.Outcome.DENY);
        assertThat(denyCaptor.getValue().event())
                .isEqualTo(OperationalAuditEvent.EventType.CONFIG_REJECTED);

        // PERMIT must never be called
        verify(auditPort, never()).recordPermit(any());
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    private OperationalConfigDescriptor buildDescriptor(
            DbTdeOperationalConfig config, long version) {
        Instant now = Instant.now();
        return new OperationalConfigDescriptor(
                UUID.randomUUID(),
                KeyManager.DB_TDE,
                config,
                true,
                ActivationStatus.ACTIVE,
                Optional.of(now),
                version,
                ACTOR,
                now
        );
    }

}
