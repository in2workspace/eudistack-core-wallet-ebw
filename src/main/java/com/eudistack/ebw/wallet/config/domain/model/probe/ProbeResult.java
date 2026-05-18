package com.eudistack.ebw.wallet.config.domain.model.probe;

/**
 * Sealed result type for a key-manager connectivity probe.
 *
 * <p>Returned by {@code KeyManagerConnectivityPort.probe(KeyManager, OperationalConfig)}.
 * The caller (e.g. {@code OperationalConfigWriter}) switches exhaustively over the three
 * permitted subtypes:
 * <ul>
 *   <li>{@link Ok} — the probe completed successfully within the timeout; carries the
 *       round-trip latency in milliseconds for OpenTelemetry reporting.</li>
 *   <li>{@link Failed} — the probe detected a connectivity or access problem; carries a
 *       functional description of the failure suitable for inclusion in audit events and
 *       {@code Problem Details} responses (no raw AWS / infrastructure detail).</li>
 *   <li>{@link NotRegistered} — no {@code ProbeAdapter} has been registered for the
 *       requested {@code KeyManager} in the current Story. In MVP, this means the writer
 *       rejected the request before reaching the probe (AD-S1); the probe registry
 *       returns this variant as a safety net for any key_manager that does not yet have
 *       an adapter (US-05/06/07 register their adapters when those Stories land).</li>
 * </ul>
 */
public sealed interface ProbeResult permits ProbeResult.Ok, ProbeResult.Failed,
        ProbeResult.NotRegistered {

    /**
     * Successful probe — the key-manager connectivity was verified within the timeout.
     *
     * @param latencyMs the measured round-trip latency in milliseconds (non-negative)
     */
    record Ok(long latencyMs) implements ProbeResult {

        /**
         * Compact constructor — validates that latency is non-negative.
         */
        public Ok {
            if (latencyMs < 0) {
                throw new IllegalArgumentException(
                        "latencyMs must be non-negative, got: " + latencyMs);
            }
        }
    }

    /**
     * Failed probe — a connectivity or access problem prevented the verification.
     *
     * @param reason a short functional description of the failure suitable for audit events
     *               and {@code Problem Details} responses; must not contain raw infrastructure
     *               error messages or secret material
     */
    record Failed(String reason) implements ProbeResult {

        /**
         * Compact constructor — validates that reason is non-null and non-empty.
         */
        public Failed {
            if (reason == null || reason.isBlank()) {
                throw new IllegalArgumentException("reason must be non-null and non-blank");
            }
        }
    }

    /**
     * No probe adapter is registered for the requested key manager.
     *
     * <p>In MVP the {@code OperationalConfigWriter} rejects unsupported key managers before
     * reaching the probe (AD-S1), so this variant is returned by the registry only as a
     * safety net. Future Stories (US-05/06/07) register their adapters and remove this
     * as the effective path for their respective key managers.
     */
    record NotRegistered() implements ProbeResult {
    }
}
