package com.eudistack.ebw.keymanager.domain.port;

import java.time.Duration;

/**
 * Port for hybrid (Passkey PRF) key-manager telemetry — PRF gate attempts/passes, sign
 * latency/errors, and wrap-handle counts. Implementations publish these as metrics
 * (e.g. Micrometer) without coupling the application layer to the metrics library.
 *
 * <p>Spec: EUDISTACK-533/536/537/538/540 observability requirements.</p>
 */
public interface HybridKeyManagerTelemetryPort {

    void recordPrfAttempt(String tenant);

    void recordPrfPass(String tenant);

    void recordSignLatency(Duration duration, String tenant);

    void recordSignError(String tenant);

    void updateWrapHandlesTotal(String tenant, long count);
}
