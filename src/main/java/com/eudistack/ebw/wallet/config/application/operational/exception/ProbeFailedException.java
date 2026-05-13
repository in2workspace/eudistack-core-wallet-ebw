package com.eudistack.ebw.wallet.config.application.operational.exception;

import java.util.Objects;

/**
 * Thrown by {@code OperationalConfigWriter} when the key-manager connectivity probe returns
 * {@link com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult.Failed} or
 * {@link com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult.NotRegistered}.
 *
 * <p>Maps to HTTP {@code 424 Failed Dependency} at the controller layer (Task 8).
 * The {@link #reason()} is a functional description suitable for inclusion in
 * {@code Problem Details} (RFC 9457) — it never contains raw infrastructure error detail
 * or secret material (AC-4d).
 *
 * <p>No Spring annotations on this class: it is a plain domain-application exception.
 */
public class ProbeFailedException extends RuntimeException {

    private final String reason;

    /**
     * @param reason a short functional description of the probe failure; must not be blank
     */
    public ProbeFailedException(String reason) {
        super("key-manager connectivity probe failed: "
                + Objects.requireNonNull(reason, "reason must not be null"));
        if (reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        this.reason = reason;
    }

    /**
     * Returns the functional reason for the probe failure.
     * Safe for inclusion in {@code Problem Details} and audit events.
     */
    public String reason() {
        return reason;
    }
}
