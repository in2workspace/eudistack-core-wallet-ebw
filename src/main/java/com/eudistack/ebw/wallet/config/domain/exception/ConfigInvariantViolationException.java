package com.eudistack.ebw.wallet.config.domain.exception;

/**
 * Thrown when a wallet configuration request violates a domain invariant.
 *
 * <p>Example: attempting to set {@code key_manager} on a BROWSER-mode tenant
 * violates invariant FR-20.
 *
 * <p>Maps to HTTP 409 Conflict at the controller boundary (RFC 9457 body).
 */
public class ConfigInvariantViolationException extends RuntimeException {

    private final String conflictingField;
    private final String receivedValue;

    public ConfigInvariantViolationException(String conflictingField, String receivedValue) {
        super(String.format(
                "Invariant violation on field '%s': received value '%s' is not permitted.",
                conflictingField, receivedValue));
        this.conflictingField = conflictingField;
        this.receivedValue = receivedValue;
    }

    public String getConflictingField() {
        return conflictingField;
    }

    public String getReceivedValue() {
        return receivedValue;
    }
}
