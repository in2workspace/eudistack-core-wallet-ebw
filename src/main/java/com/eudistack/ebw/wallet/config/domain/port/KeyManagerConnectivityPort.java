package com.eudistack.ebw.wallet.config.domain.port;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult;
import reactor.core.publisher.Mono;

/**
 * Output port — connectivity probe contract for registered key-manager adapters.
 *
 * <p>Before persisting an operational configuration, {@code OperationalConfigWriter} calls this
 * port to verify that the key-manager backend is reachable and correctly configured for the
 * current tenant. The probe runs <em>outside</em> the main writer transaction: KMS calls must
 * not be held under a database lock, and a slow probe must not block a DB connection.
 *
 * <h2>Sealed supertype as probe parameter</h2>
 * The {@code config} parameter is typed as the sealed supertype {@link OperationalConfig}
 * (approved deviation from tech-design §3.2 which originally referenced
 * {@code DbTdeOperationalConfig} directly). This deviation is intentional and future-proof:
 * <ul>
 *   <li>US-05/06/07 (HSM, QTSP, Hybrid) will add their {@code OperationalConfig} subtypes
 *       and their own {@code ProbeAdapter} implementations. Each adapter pattern-matches on
 *       the sealed type to extract the subtype-specific parameters it needs.</li>
 *   <li>The US-03 implementation ({@code DbTdeProbeAdapter}) pattern-matches and accepts only
 *       {@code DbTdeOperationalConfig} — any other subtype is an internal error (the writer
 *       rejects unsupported key managers before reaching the probe, AD-S1).</li>
 *   <li>Using the supertype here keeps the port stable across all future Stories; opening the
 *       port later to change the parameter type would be a breaking change for all adapters.</li>
 * </ul>
 *
 * <p>The implementing adapter is {@code KeyManagerProbeRegistry}, which delegates to the
 * appropriate {@code ProbeAdapter} bean for the given {@link KeyManager}. In MVP only
 * {@code DbTdeProbeAdapter} is registered; probes for other key managers return
 * {@link ProbeResult.NotRegistered} as a safety net (the writer rejects them first, AD-S1).
 *
 * <p>This interface has zero framework or infrastructure imports — it belongs to the domain layer.
 */
public interface KeyManagerConnectivityPort {

    /**
     * Executes a connectivity probe for the given key-manager and its operational configuration.
     *
     * <p>The probe verifies that the key-manager backend is reachable and correctly configured.
     * For {@code DB_TDE} this means:
     * <ol>
     *   <li>Calling {@code kms:DescribeKey} on the {@code columnEncryptionKeyArn} to verify
     *       CMK accessibility (timeout: 5 s — E-14).</li>
     *   <li>Running {@code SELECT 1 FROM wallet_operational_config_db_tde LIMIT 1} to verify
     *       that the sub-table exists in the tenant's schema (defense-in-depth — AC-5d).</li>
     * </ol>
     * If both checks pass, the result is {@link ProbeResult.Ok} with the measured latency.
     * If either check fails, the result is {@link ProbeResult.Failed} with a functional
     * description of the failure (no raw AWS / infrastructure error detail).
     * If no adapter is registered for the key manager, the result is
     * {@link ProbeResult.NotRegistered}.
     *
     * <p>Callers must not invoke this method within a database transaction: the probe opens its
     * own connections (KMS HTTP + a separate DB query) that must not be held under a DB lock.
     *
     * @param keyManager the key-manager variant to probe
     * @param config     the operational configuration for the probe; the adapter pattern-matches
     *                   on the sealed type to extract subtype-specific parameters
     * @return a {@link Mono} emitting the probe result; never emits {@code Mono.empty()}
     */
    Mono<ProbeResult> probe(KeyManager keyManager, OperationalConfig config);
}
