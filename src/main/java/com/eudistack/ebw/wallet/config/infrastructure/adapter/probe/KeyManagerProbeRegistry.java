package com.eudistack.ebw.wallet.config.infrastructure.adapter.probe;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult;
import com.eudistack.ebw.wallet.config.domain.port.KeyManagerConnectivityPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Implementation of {@link KeyManagerConnectivityPort} that dispatches probe calls to the
 * appropriate {@link ProbeAdapter} based on the requested {@link KeyManager}.
 *
 * <p>The registry holds an explicit, immutable {@code Map<KeyManager, ProbeAdapter>} assembled
 * at boot time by {@code OperationalConfigBeans} (Task 9). In US-03 (MVP), the map contains
 * exactly one entry: {@code KeyManager.DB_TDE → DbTdeProbeAdapter}. Future Stories
 * (US-05/06/07) add their entries to the map when their probe adapters are delivered.
 *
 * <h2>Safety net — {@link ProbeResult.NotRegistered}</h2>
 * If no adapter is registered for the requested {@code KeyManager}, the registry returns
 * {@link ProbeResult.NotRegistered} rather than throwing. In MVP the
 * {@code OperationalConfigWriter} (AD-S1) rejects unsupported key managers before reaching the
 * probe, so this branch is a defense-in-depth fallback — it should never be reached in practice.
 *
 * <h2>Wiring</h2>
 * This class is NOT annotated with {@code @Component}. It is instantiated by
 * {@code OperationalConfigBeans} (Task 9) following the explicit-wiring pattern established by
 * {@code WalletTenantConfigR2dbcAdapter} and {@code OperationalConfigAuditR2dbcAdapter}.
 */
public class KeyManagerProbeRegistry implements KeyManagerConnectivityPort {

    private static final Logger log = LoggerFactory.getLogger(KeyManagerProbeRegistry.class);

    private final Map<KeyManager, ProbeAdapter> adapters;

    /**
     * Constructs the registry with the given adapter map.
     *
     * <p>The map is assembled by {@code OperationalConfigBeans} using
     * {@code Map.of(KeyManager.DB_TDE, dbTdeProbeAdapter)} in Task 9. The map must be
     * non-null; an empty map is valid but means all probes return {@link ProbeResult.NotRegistered}.
     *
     * @param adapters the key-manager-to-adapter map; must be non-null
     */
    public KeyManagerProbeRegistry(Map<KeyManager, ProbeAdapter> adapters) {
        if (adapters == null) {
            throw new IllegalArgumentException("adapters map must not be null");
        }
        this.adapters = adapters;
    }

    /**
     * Dispatches the probe to the registered adapter for the given {@code keyManager}.
     *
     * <p>If no adapter is registered for the key manager, returns {@link ProbeResult.NotRegistered}
     * immediately without any I/O. Otherwise, delegates to
     * {@link ProbeAdapter#probe(OperationalConfig)}.
     *
     * @param keyManager the key-manager variant to probe
     * @param config     the operational configuration; passed as-is to the delegate adapter
     * @return a {@link Mono} emitting the probe result; never emits {@code Mono.empty()}
     */
    @Override
    public Mono<ProbeResult> probe(KeyManager keyManager, OperationalConfig config) {
        ProbeAdapter adapter = adapters.get(keyManager);
        if (adapter == null) {
            log.debug("probe: no adapter registered for keyManager={} — returning NotRegistered",
                    keyManager);
            return Mono.just(new ProbeResult.NotRegistered());
        }
        return adapter.probe(config);
    }
}
