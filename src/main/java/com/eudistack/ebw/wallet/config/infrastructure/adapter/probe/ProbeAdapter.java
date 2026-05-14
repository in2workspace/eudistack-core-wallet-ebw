package com.eudistack.ebw.wallet.config.infrastructure.adapter.probe;

import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult;
import reactor.core.publisher.Mono;

/**
 * Internal SPI for key-manager-specific connectivity probes.
 *
 * <p>Each {@code ProbeAdapter} implementation handles exactly one {@link
 * com.eudistack.ebw.wallet.config.domain.model.KeyManager} variant. The adapter pattern-matches
 * on the sealed {@link OperationalConfig} supertype to extract the subtype-specific parameters
 * it needs (e.g. {@code columnEncryptionKeyArn} for {@code db-tde}).
 *
 * <p>This interface is infrastructure-internal: it is used only by {@link KeyManagerProbeRegistry}
 * to dispatch probe calls to the correct implementation. It is NOT a domain port — it must not be
 * referenced by application or domain layer classes.
 *
 * <h2>Wiring</h2>
 * Implementations are NOT annotated with {@code @Component}. They are instantiated and wired
 * into the {@link KeyManagerProbeRegistry} by {@code OperationalConfigBeans} (Task 9) using an
 * explicit {@code Map.of(KeyManager.DB_TDE, dbTdeProbeAdapter)} map.
 */
interface ProbeAdapter {

    /**
     * Executes a connectivity probe using the given operational configuration.
     *
     * <p>The implementation pattern-matches on the sealed {@code config} type to extract
     * subtype-specific parameters. If the received type does not match the expected subtype,
     * the implementation signals {@link IllegalArgumentException} — the registry's caller
     * ({@code OperationalConfigWriter}) is responsible for ensuring type coherence (AD-S1).
     *
     * @param config the operational configuration for the probe; must be the subtype expected
     *               by this adapter
     * @return a {@link Mono} emitting the probe result; never emits {@code Mono.empty()}
     */
    Mono<ProbeResult> probe(OperationalConfig config);
}
