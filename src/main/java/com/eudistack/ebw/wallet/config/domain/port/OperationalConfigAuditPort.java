package com.eudistack.ebw.wallet.config.domain.port;

import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalAuditEvent;
import reactor.core.publisher.Mono;

/**
 * Output port — append-only write contract for operational-config audit events.
 *
 * <p>Every write attempt through {@code OperationalConfigWriter} — whether it succeeds or fails —
 * produces an {@link OperationalAuditEvent} that is persisted to
 * {@code wallet_config_audit} with {@code plane='operational'}. The table is guarded by the
 * append-only trigger {@code trg_wallet_config_audit_append_only} (delivered by EUDISTACK-412),
 * which rejects any {@code UPDATE} or {@code DELETE}.
 *
 * <h2>Intent vs. propagation</h2>
 * This port expresses <em>intent</em> only — it does not prescribe the transactional propagation.
 * The implementing adapter ({@code OperationalConfigAuditR2dbcAdapter}) is responsible for
 * wrapping each call in a separate transaction with {@code Propagation.REQUIRES_NEW} (AD-S4 in
 * tech-design §3.5). This ensures that:
 * <ul>
 *   <li>An audit record for a <em>denied</em> operation persists even when the main writer
 *       transaction is rolled back (AC-4b, AC-4c).</li>
 *   <li>An audit record for a <em>permitted</em> operation is committed before the main
 *       transaction commits, so the audit trail can never be orphaned.</li>
 * </ul>
 * Any future adapter implementation (e.g. Kafka event bridge) must preserve the same
 * at-least-once, ordered-delivery guarantee; the {@code REQUIRES_NEW} detail is an adapter
 * concern, not a port concern.
 *
 * <p>This interface has zero framework or infrastructure imports — it belongs to the domain layer.
 * The implementing adapter lives in {@code infrastructure/adapter/r2dbc}.
 */
public interface OperationalConfigAuditPort {

    /**
     * Records a successful operation as a {@code PERMIT} audit event.
     *
     * <p>Called by {@code OperationalConfigWriter} after the main transaction successfully
     * commits. The event type is typically {@code CONFIG_APPLIED} or
     * {@code CONNECTIVITY_VERIFIED}. The {@link OperationalAuditEvent#outcome()} must be
     * {@link OperationalAuditEvent.Outcome#PERMIT}.
     *
     * <p>Secret fields (e.g. {@code wrapped_dek}) must already be redacted in
     * {@link OperationalAuditEvent#fieldChanges()} before calling this method — use
     * {@link OperationalAuditEvent#withSecretFieldRedacted(String, boolean)} when building
     * the event (AC-4d).
     *
     * @param event the audit event to persist; must not be null
     * @return a {@link Mono} that completes empty when the record has been persisted,
     *         or terminates with an error if the insert fails
     */
    Mono<Void> recordPermit(OperationalAuditEvent event);

    /**
     * Records a failed or rejected operation as a {@code DENY} audit event.
     *
     * <p>Called by {@code OperationalConfigWriter} when the operation is rejected before or
     * after opening the main transaction (validation failure, probe failure, optimistic-lock
     * conflict, mid-transaction constraint violation). The event type is typically
     * {@code CONFIG_REJECTED} or {@code CONNECTIVITY_FAILED}. The
     * {@link OperationalAuditEvent#outcome()} must be
     * {@link OperationalAuditEvent.Outcome#DENY}.
     *
     * <p>Because the main transaction may have already been rolled back at the point this method
     * is called, the adapter runs the insert in a {@code REQUIRES_NEW} transaction (AD-S4) to
     * guarantee persistence regardless of the outer transactional state. The {@code reason}
     * field must describe the cause in functional terms without exposing raw infrastructure
     * error messages or secret values (AC-4d).
     *
     * @param event the audit event to persist; must not be null
     * @return a {@link Mono} that completes empty when the record has been persisted,
     *         or terminates with an error if the insert fails
     */
    Mono<Void> recordDeny(OperationalAuditEvent event);
}
