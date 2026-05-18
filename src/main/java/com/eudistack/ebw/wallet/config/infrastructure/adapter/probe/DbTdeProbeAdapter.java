package com.eudistack.ebw.wallet.config.infrastructure.adapter.probe;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.DbTdeOperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult;
import com.eudistack.ebw.wallet.config.domain.port.EnvelopeEncryptionPort;
import com.eudistack.ebw.wallet.config.domain.port.OperationalConfigPort;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.kms.KmsAccessException;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * {@code db-tde} specific implementation of {@link ProbeAdapter}.
 *
 * <p>The probe executes two sequential checks outside of any database transaction:
 * <ol>
 *   <li><b>KMS CMK accessibility</b> — calls
 *       {@link EnvelopeEncryptionPort#verifyCmkAccessible(String)} with the ARN from the
 *       supplied {@link DbTdeOperationalConfig}. This uses {@code kms:DescribeKey} (no key
 *       material is retrieved). Timeout: 5 s (configured on the {@link EnvelopeEncryptionPort}
 *       implementation — E-14).</li>
 *   <li><b>Sub-table accessibility</b> — calls
 *       {@link OperationalConfigPort#canQuerySubtable(KeyManager)} with
 *       {@link KeyManager#DB_TDE}. Returns {@code true} if the tenant's
 *       {@code wallet_operational_config_db_tde} table is accessible (AC-5d).</li>
 * </ol>
 *
 * <p>If both checks pass, emits {@link ProbeResult.Ok} with the measured round-trip latency in
 * milliseconds. If either check fails, emits {@link ProbeResult.Failed} with a functional
 * description of the failure — no raw AWS error bodies or infrastructure detail.
 *
 * <h2>OTEL span (E-5)</h2>
 * The probe chain is wrapped with a Micrometer {@link Observation} named
 * {@code wallet.operational.probe} with low-cardinality key {@code key_manager=db-tde}.
 * The observation lifecycle (start → stop/error) is managed explicitly using
 * {@link Mono#using} so the span is properly closed whether the chain completes normally,
 * signals an error, or is cancelled by the subscriber.
 *
 * <h2>Defensive guard — sealed type mismatch</h2>
 * The first step pattern-matches on the sealed {@link OperationalConfig}. If {@code config}
 * is not a {@link DbTdeOperationalConfig}, the probe immediately signals
 * {@link IllegalArgumentException}. This guards against programming errors: the
 * {@code OperationalConfigWriter} (AD-S1) guarantees that only {@code DB_TDE} reaches this
 * adapter; if the invariant is broken, the error is caught by the calling chain.
 *
 * <h2>Wiring</h2>
 * This class is NOT annotated with {@code @Component}. It is instantiated by
 * {@code OperationalConfigBeans} (Task 9) following the explicit-wiring pattern.
 */
public class DbTdeProbeAdapter implements ProbeAdapter {

    private static final Logger log = LoggerFactory.getLogger(DbTdeProbeAdapter.class);

    private static final String OBSERVATION_NAME = "wallet.operational.probe";
    private static final String KEY_MANAGER_TAG_KEY = "key_manager";
    private static final String KEY_MANAGER_TAG_VALUE = "db-tde";

    private final EnvelopeEncryptionPort envelopeEncryptionPort;
    private final OperationalConfigPort operationalConfigPort;
    private final ObservationRegistry observationRegistry;

    /**
     * Constructs the adapter.
     *
     * @param envelopeEncryptionPort the KMS port used for CMK accessibility verification
     * @param operationalConfigPort  the operational config port used for sub-table accessibility
     * @param observationRegistry    the Micrometer registry used to create OpenTelemetry spans
     */
    public DbTdeProbeAdapter(
            EnvelopeEncryptionPort envelopeEncryptionPort,
            OperationalConfigPort operationalConfigPort,
            ObservationRegistry observationRegistry) {
        this.envelopeEncryptionPort = envelopeEncryptionPort;
        this.operationalConfigPort = operationalConfigPort;
        this.observationRegistry = observationRegistry;
    }

    /**
     * Executes the two-step {@code db-tde} connectivity probe wrapped in an OTEL span.
     *
     * <p>Step 1 — Guard: pattern-match on {@code config}; if not {@link DbTdeOperationalConfig},
     * signal {@link IllegalArgumentException}.<br>
     * Step 2 — KMS check: {@code verifyCmkAccessible(cmkArn)}.<br>
     * Step 3 — Sub-table check: {@code canQuerySubtable(DB_TDE)}.<br>
     * Step 4 — Emit result: {@link ProbeResult.Ok} with latency, or {@link ProbeResult.Failed}
     * if the sub-table is not accessible.<br>
     * Error handling: {@link KmsAccessException} → {@link ProbeResult.Failed} with a
     * {@code "kms: ..."} message; any other error → {@link ProbeResult.Failed} with the class
     * simple name; {@link IllegalArgumentException} from the guard → propagated as an error
     * (not converted to Failed — it is a programming error, not a connectivity failure).
     *
     * @param config the operational configuration; must be a {@link DbTdeOperationalConfig}
     * @return a {@link Mono} emitting the probe result; never emits {@code Mono.empty()}
     */
    @Override
    public Mono<ProbeResult> probe(OperationalConfig config) {
        if (!(config instanceof DbTdeOperationalConfig db)) {
            return Mono.error(new IllegalArgumentException(
                    "DbTdeProbeAdapter expects DbTdeOperationalConfig but received: "
                            + (config == null ? "null" : config.getClass().getSimpleName())));
        }
        return Mono.using(
                () -> startObservation(),
                observation -> executeProbeChain(db, observation),
                observation -> observation.stop()
        );
    }

    // --- Private helpers ---

    /**
     * Creates and starts a Micrometer {@link Observation} for this probe invocation.
     *
     * <p>Low-cardinality key {@code key_manager=db-tde} is attached so the span can be
     * grouped by key manager type in dashboards without creating high-cardinality dimensions.
     *
     * @return the started {@link Observation}
     */
    private Observation startObservation() {
        return Observation.createNotStarted(OBSERVATION_NAME, observationRegistry)
                .lowCardinalityKeyValue(KEY_MANAGER_TAG_KEY, KEY_MANAGER_TAG_VALUE)
                .start();
    }

    /**
     * Core probe chain: measures latency, calls KMS and sub-table checks, maps results.
     *
     * <p>Uses {@link Mono#defer} so {@code startNanos} is captured per-subscription (AC-5).
     *
     * @param db          the {@code db-tde} configuration with the CMK ARN
     * @param observation the active span; error is signalled to it before the chain terminates
     * @return a {@link Mono} emitting the probe result
     */
    private Mono<ProbeResult> executeProbeChain(DbTdeOperationalConfig db,
            Observation observation) {
        return Mono.defer(() -> {
            long startNanos = System.nanoTime();
            return envelopeEncryptionPort.verifyCmkAccessible(db.columnEncryptionKeyArn())
                    .then(operationalConfigPort.canQuerySubtable(KeyManager.DB_TDE))
                    .flatMap(subtableOk -> {
                        long latencyMs = (System.nanoTime() - startNanos) / 1_000_000;
                        if (subtableOk) {
                            log.debug(
                                    "probe outcome=ok keyManager=db-tde latencyMs={}", latencyMs);
                            return Mono.<ProbeResult>just(new ProbeResult.Ok(latencyMs));
                        }
                        log.debug("probe outcome=fail keyManager=db-tde "
                                + "reason=db-tde subtable not accessible");
                        return Mono.<ProbeResult>just(
                                new ProbeResult.Failed("db-tde subtable not accessible"));
                    })
                    .onErrorResume(KmsAccessException.class, e -> {
                        String reason = "kms: " + e.getMessage();
                        log.debug("probe outcome=fail keyManager=db-tde reason={}", reason);
                        observation.error(e);
                        return Mono.just(new ProbeResult.Failed(reason));
                    })
                    .onErrorResume(IllegalArgumentException.class, e -> {
                        log.debug("probe outcome=fail keyManager=db-tde "
                                + "reason=internal error: config type mismatch");
                        observation.error(e);
                        return Mono.just(
                                new ProbeResult.Failed("internal error: config type mismatch"));
                    })
                    .onErrorResume(e -> {
                        String reason = e.getClass().getSimpleName();
                        log.debug("probe outcome=fail keyManager=db-tde reason={}", reason);
                        observation.error(e);
                        return Mono.just(new ProbeResult.Failed(reason));
                    });
        });
    }
}
