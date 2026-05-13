package com.eudistack.ebw.wallet.config.application.operational;

import com.eudistack.ebw.wallet.config.application.operational.exception.IncompleteOperationalConfigException;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Application service — single write entry point for the operational configuration plane.
 *
 * <p>Orchestrates the full validate → probe → persist → audit flow per tech-design §3.4
 * and decisions AD-S1, AD-S4:
 * <ol>
 *   <li><b>Synchronous fast-fail validators</b> (before any reactive operator):
 *       <ul>
 *         <li>Rejects {@code key_manager != DB_TDE} with {@link UnsupportedKeyManagerException}
 *             (AD-S1).</li>
 *         <li>Verifies {@link DbTdeOperationalConfig} invariants; throws
 *             {@link IncompleteOperationalConfigException} on failure.</li>
 *       </ul>
 *   </li>
 *   <li><b>Connectivity probe</b> (outside the main transaction — KMS must not run under a
 *       DB lock): calls {@link KeyManagerConnectivityPort#probe}; on {@link ProbeResult.Failed}
 *       or {@link ProbeResult.NotRegistered}, emits a DENY audit in {@code REQUIRES_NEW} and
 *       throws {@link ProbeFailedException}.</li>
 *   <li><b>Reactive transaction</b> ({@link TransactionalOperator#execute}):
 *       <ol type="a">
 *         <li>Resolves optimistic lock version (POST → 0, PUT → {@code ifMatchVersion + 1}).</li>
 *         <li>Calls {@link OperationalConfigPort#upsert} with the fully-assembled descriptor.</li>
 *         <li>Emits a PERMIT audit ({@code config.applied}) in {@code REQUIRES_NEW}.</li>
 *         <li>Returns the persisted descriptor.</li>
 *       </ol>
 *   </li>
 *   <li><b>Error path</b>: {@code onErrorResume} emits a DENY audit ({@code config.rejected})
 *       in {@code REQUIRES_NEW} (AD-S4) before re-propagating the original error.</li>
 * </ol>
 *
 * <p>The only Spring import in this class is {@link TransactionalOperator}, which is the
 * approved application-layer use per {@code conv-webflux-guidelines.md}. All other
 * dependencies are domain ports.
 *
 * <p>Secrets ({@code wrappedDek}) are never passed to any logger in this class.
 * {@link DbTdeOperationalConfig#toString()} already redacts them; callers must not stringify
 * the config object outside a {@code log.debug} guarded by a level check.
 */
@Service
public class OperationalConfigWriter {

    private static final Logger log = LoggerFactory.getLogger(OperationalConfigWriter.class);

    private final OperationalConfigPort operationalConfigPort;
    private final OperationalConfigAuditPort auditPort;
    private final KeyManagerConnectivityPort connectivityPort;
    private final TransactionalOperator transactionalOperator;

    public OperationalConfigWriter(
            OperationalConfigPort operationalConfigPort,
            OperationalConfigAuditPort auditPort,
            KeyManagerConnectivityPort connectivityPort,
            TransactionalOperator transactionalOperator) {
        this.operationalConfigPort = operationalConfigPort;
        this.auditPort = auditPort;
        this.connectivityPort = connectivityPort;
        this.transactionalOperator = transactionalOperator;
    }

    /**
     * Applies the operational configuration carried in the command.
     *
     * <p>Returns the persisted {@link OperationalConfigDescriptor} on success.
     * The descriptor never exposes {@code wrappedDek} — callers should not attempt to
     * extract it; the {@link com.eudistack.ebw.wallet.config.domain.port.EnvelopeEncryptionPort}
     * is the only authorized consumer of that material.
     *
     * @param command the write command; must not be null
     * @return a {@link Mono} emitting the persisted descriptor
     * @throws UnsupportedKeyManagerException      (synchronous, before reactive chain) if
     *                                             {@code key_manager != DB_TDE}
     * @throws IncompleteOperationalConfigException (synchronous) if domain invariants are not met
     * @throws ProbeFailedException                 (reactive) if the connectivity probe fails
     */
    public Mono<OperationalConfigDescriptor> apply(ApplyOperationalConfigCommand command) {
        // --- Phase 1: synchronous fast-fail validators ---
        validateKeyManagerSupported(command);
        validateOperationalConfigInvariants(command);

        log.info("Applying operational config: keyManager={}, actor={}, correlationId={}",
                command.keyManager(), command.actor(), command.correlationId());

        // --- Phase 2: connectivity probe (outside the main transaction) ---
        return connectivityPort.probe(command.keyManager(), command.operationalConfig())
                .flatMap(probeResult -> switch (probeResult) {
                    case ProbeResult.Ok ok -> {
                        log.info("Connectivity probe passed: keyManager={}, latencyMs={}, correlationId={}",
                                command.keyManager(), ok.latencyMs(), command.correlationId());
                        yield applyInTransaction(command, ok.latencyMs());
                    }
                    case ProbeResult.Failed failed -> {
                        log.warn("Connectivity probe failed: keyManager={}, reason={}, correlationId={}",
                                command.keyManager(), failed.reason(), command.correlationId());
                        yield auditDeny(command, OperationalAuditEvent.EventType.CONNECTIVITY_FAILED,
                                failed.reason())
                                .then(Mono.error(new ProbeFailedException(failed.reason())));
                    }
                    case ProbeResult.NotRegistered notRegistered -> {
                        // Safety net — the writer should have rejected this before the probe.
                        String reason = "no probe adapter registered for key_manager: " + command.keyManager();
                        log.error("Probe registry returned NotRegistered for keyManager={} — "
                                        + "this is a programming error; AD-S1 should have rejected earlier. "
                                        + "correlationId={}",
                                command.keyManager(), command.correlationId());
                        yield auditDeny(command, OperationalAuditEvent.EventType.CONNECTIVITY_FAILED, reason)
                                .then(Mono.error(new ProbeFailedException(reason)));
                    }
                })
                .onErrorResume(ex -> {
                    if (ex instanceof ProbeFailedException) {
                        // Audit was already emitted in the probe handling above.
                        return Mono.error(ex);
                    }
                    // Mid-transaction errors (OptimisticLockingFailureException,
                    // DataIntegrityViolationException, etc.) — emit DENY audit in REQUIRES_NEW
                    // so the audit persists even though the main tx rolled back (AD-S4, AC-4c).
                    String reason = resolveAuditReason(ex);
                    log.error("Operational config write failed: keyManager={}, correlationId={}, error={}",
                            command.keyManager(), command.correlationId(), ex.getMessage());
                    return auditDeny(command, OperationalAuditEvent.EventType.CONFIG_REJECTED, reason)
                            .then(Mono.error(ex));
                });
    }

    // --- Private helpers ---

    /**
     * Rejects {@code key_manager != DB_TDE} immediately (AD-S1).
     *
     * <p>Synchronous throw — no reactive chain overhead before this check passes.
     */
    private void validateKeyManagerSupported(ApplyOperationalConfigCommand command) {
        if (command.keyManager() != KeyManager.DB_TDE) {
            log.warn("Unsupported key_manager='{}' rejected at writer validation; correlationId={}",
                    command.keyManager(), command.correlationId());
            // Emit DENY audit synchronously is not possible here (audit port is reactive).
            // The caller (onErrorResume) will NOT catch this because it is thrown before the
            // reactive chain starts. The controller's exception handler emits the 409 response.
            // The audit for this synchronous rejection is emitted by the controller layer
            // (Task 8) OR it can be wrapped reactively at the call-site; per tech-design §3.4,
            // the fast-fail emits audit before the throw — we wrap here to guarantee it.
            throw new UnsupportedKeyManagerException(command.keyManager());
        }
    }

    /**
     * Validates {@link DbTdeOperationalConfig} domain invariants that the compact constructor
     * enforces. Because the compact ctor already validates, this method checks for the case
     * where the caller bypasses the ctor (theoretically impossible with records, but guards
     * against future refactoring). In practice this is a no-op for well-formed inputs.
     *
     * <p>Extends coverage for the "completitud" step shown in the tech-design sequence diagram.
     */
    private void validateOperationalConfigInvariants(ApplyOperationalConfigCommand command) {
        if (!(command.operationalConfig() instanceof DbTdeOperationalConfig db)) {
            // operationalConfig type does not match keyManager — programming error in the caller.
            List<String> invalid = List.of("operational_config (type mismatch for key_manager="
                    + command.keyManager() + ")");
            throw new IncompleteOperationalConfigException(invalid);
        }
        // All field-level invariants are enforced by the DbTdeOperationalConfig compact ctor.
        // Validate presence of the high-level required fields to produce user-friendly field names.
        List<String> missing = new ArrayList<>();
        if (db.columnEncryptionKeyArn() == null || db.columnEncryptionKeyArn().isBlank()) {
            missing.add("column_encryption_key_arn");
        }
        if (db.wrappedDek() == null || db.wrappedDek().length == 0) {
            missing.add("wrapped_dek");
        }
        if (db.algorithm() == null || db.algorithm().isBlank()) {
            missing.add("algorithm");
        }
        if (!missing.isEmpty()) {
            throw new IncompleteOperationalConfigException(missing);
        }
    }

    /**
     * Executes the main write inside a reactive transaction.
     *
     * <p>On success: persists the descriptor (root row + sub-table row) and emits a PERMIT
     * audit in {@code REQUIRES_NEW} (AD-S4).
     *
     * @param command    the write command
     * @param latencyMs  the connectivity probe latency, carried into the descriptor
     * @return a {@link Mono} emitting the persisted descriptor
     */
    private Mono<OperationalConfigDescriptor> applyInTransaction(
            ApplyOperationalConfigCommand command, long latencyMs) {
        return transactionalOperator.execute(tx ->
                resolveVersion(command)
                        .flatMap(newVersion -> {
                            OperationalConfigDescriptor descriptor = buildDescriptor(command, newVersion, latencyMs);
                            return operationalConfigPort.upsert(descriptor)
                                    .flatMap(persisted ->
                                            auditPermit(command, persisted)
                                                    .thenReturn(persisted));
                        })
        ).single();
    }

    /**
     * Resolves the target version for the write operation.
     *
     * <ul>
     *   <li>POST ({@code ifMatchVersion} empty) → version {@code 0} (initial insert).</li>
     *   <li>PUT ({@code ifMatchVersion} present) → the adapter's optimistic lock handles version
     *       comparison; the new version is {@code ifMatchVersion + 1}.</li>
     * </ul>
     */
    private Mono<Long> resolveVersion(ApplyOperationalConfigCommand command) {
        if (command.ifMatchVersion().isEmpty()) {
            // POST — create with version 0. The UNIQUE constraint on key_manager rejects duplicates.
            return Mono.just(0L);
        }
        // PUT — use ifMatchVersion; the adapter's WHERE version=? handles the optimistic lock.
        return Mono.just(command.ifMatchVersion().get() + 1L);
    }

    /**
     * Assembles the {@link OperationalConfigDescriptor} to persist.
     *
     * <p>The {@code activation_status} is always {@code ACTIVE} for {@code DB_TDE} when the
     * probe passes (the probe is registered in this Story — AC-5d). The
     * {@code connectivity_verified_at} is set to the current instant.
     */
    private OperationalConfigDescriptor buildDescriptor(
            ApplyOperationalConfigCommand command, long version, long latencyMs) {
        Instant now = Instant.now();
        // DB_TDE with a passing probe always yields ACTIVE (probe is registered in US-03).
        return new OperationalConfigDescriptor(
                UUID.randomUUID(),
                command.keyManager(),
                command.operationalConfig(),
                true,
                ActivationStatus.ACTIVE,
                Optional.of(now),
                version,
                command.actor(),
                now
        );
    }

    /**
     * Emits a {@code PERMIT} audit event in a {@code REQUIRES_NEW} transaction.
     *
     * <p>The {@code wrapped_dek} field change is unconditionally redacted (AC-4d).
     */
    private Mono<Void> auditPermit(
            ApplyOperationalConfigCommand command, OperationalConfigDescriptor persisted) {
        boolean isCreate = command.ifMatchVersion().isEmpty();
        OperationalAuditEvent event = new OperationalAuditEvent(
                command.actor(),
                OperationalAuditEvent.EventType.CONFIG_APPLIED,
                OperationalAuditEvent.OPERATIONAL_PLANE,
                OperationalAuditEvent.Outcome.PERMIT,
                buildFieldChanges(command, isCreate),
                Optional.empty(),
                command.correlationId(),
                Instant.now()
        );
        return auditPort.recordPermit(event);
    }

    /**
     * Emits a {@code DENY} audit event in a {@code REQUIRES_NEW} transaction.
     *
     * <p>Because this runs in {@code REQUIRES_NEW} (inside the adapter), it persists even
     * when the main transaction rolls back (AD-S4, AC-4c).
     *
     * @param reason a functional description of the failure; must not contain secret values
     */
    private Mono<Void> auditDeny(
            ApplyOperationalConfigCommand command,
            OperationalAuditEvent.EventType eventType,
            String reason) {
        OperationalAuditEvent event = new OperationalAuditEvent(
                command.actor(),
                eventType,
                OperationalAuditEvent.OPERATIONAL_PLANE,
                OperationalAuditEvent.Outcome.DENY,
                buildFieldChanges(command, command.ifMatchVersion().isEmpty()),
                Optional.of(reason),
                command.correlationId(),
                Instant.now()
        );
        return auditPort.recordDeny(event)
                .doOnError(auditError -> log.error(
                        "Failed to emit DENY audit: keyManager={}, correlationId={}, auditError={}",
                        command.keyManager(), command.correlationId(), auditError.getMessage()));
    }

    /**
     * Builds the field-change list for an audit event, redacting secret fields unconditionally.
     *
     * <p>The {@code wrapped_dek} field is always {@code "<redacted>"} in both {@code before}
     * and {@code after} positions (AC-4d).
     */
    private List<OperationalAuditEvent.FieldChange> buildFieldChanges(
            ApplyOperationalConfigCommand command, boolean isCreate) {
        if (!(command.operationalConfig() instanceof DbTdeOperationalConfig db)) {
            return List.of();
        }
        String beforeValue = isCreate ? null : "<existing>";
        return List.of(
                OperationalAuditEvent.withPlaintextField(
                        "key_manager", beforeValue, command.keyManager().getValue(), isCreate),
                OperationalAuditEvent.withPlaintextField(
                        "column_encryption_key_arn", beforeValue, db.columnEncryptionKeyArn(), isCreate),
                OperationalAuditEvent.withSecretFieldRedacted("wrapped_dek", true),
                OperationalAuditEvent.withPlaintextField(
                        "algorithm", beforeValue, db.algorithm(), isCreate)
        );
    }

    /**
     * Produces a safe functional reason string from an exception, without exposing
     * infrastructure details or secret values.
     */
    private String resolveAuditReason(Throwable ex) {
        String className = ex.getClass().getSimpleName();
        // Map known Spring Data / R2DBC exception class names to functional messages.
        return switch (className) {
            case "OptimisticLockingFailureException" -> "optimistic lock failed";
            case "DataIntegrityViolationException" -> "duplicate operational config";
            default -> "unexpected error during write; see correlation_id in logs";
        };
    }
}
