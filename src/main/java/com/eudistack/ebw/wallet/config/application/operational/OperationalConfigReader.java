package com.eudistack.ebw.wallet.config.application.operational;

import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.port.OperationalConfigPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Application service — read-only access to the operational configuration plane.
 *
 * <p>Delegates to {@link OperationalConfigPort#findActive()} and wraps the result with
 * structured logging. The tenant is resolved from the reactive context inside the adapter
 * ({@code Mono.deferContextual} in {@code OperationalConfigR2dbcAdapter}) — no explicit
 * tenant parameter is needed here.
 *
 * <p>When US-08 (health endpoint, {@code wallet-ebw/admin/health}) is implemented, it will
 * consume this service to report {@code activation_status} for the current tenant.
 *
 * <p>This class is intentionally minimal: the port contract is the source of truth;
 * this service provides a stable facade so future readers (health, metrics) do not depend
 * on the port directly.
 */
@Service
public class OperationalConfigReader {

    private static final Logger log = LoggerFactory.getLogger(OperationalConfigReader.class);

    private final OperationalConfigPort operationalConfigPort;

    public OperationalConfigReader(OperationalConfigPort operationalConfigPort) {
        this.operationalConfigPort = operationalConfigPort;
    }

    /**
     * Returns the currently active operational configuration descriptor for the current tenant,
     * or {@link Optional#empty()} if no active configuration has been applied yet.
     *
     * <p>Never returns a {@code Mono.empty()} signal — the presence/absence is always represented
     * as a {@code Mono<Optional>} (dual-read semantics of the port, documented in
     * {@link OperationalConfigPort#findActive()}).
     *
     * @return a {@link Mono} emitting an {@link Optional} wrapping the active descriptor,
     *         or {@link Optional#empty()} if no active configuration exists
     */
    public Mono<Optional<OperationalConfigDescriptor>> findActive() {
        log.debug("Reading active operational config descriptor");
        return operationalConfigPort.findActive()
                .doOnSuccess(opt -> {
                    if (opt.isPresent()) {
                        log.info("Active operational config found: keyManager={}, activationStatus={}, version={}",
                                opt.get().keyManager(), opt.get().activationStatus(), opt.get().version());
                    } else {
                        log.debug("No active operational config found for current tenant");
                    }
                })
                .doOnError(ex -> log.error("Failed to read active operational config: error={}",
                        ex.getMessage()));
    }
}
