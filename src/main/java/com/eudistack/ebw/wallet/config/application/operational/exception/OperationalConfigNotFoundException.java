package com.eudistack.ebw.wallet.config.application.operational.exception;

/**
 * Thrown by {@code OperationalConfigReader} when no active operational configuration
 * exists for the current tenant.
 *
 * <p>Maps to HTTP {@code 404 Not Found} via
 * {@link com.eudistack.ebw.wallet.config.infrastructure.controller.exception.OperationalConfigExceptionHandler}
 * (AC-5: GET returns 404 if no active config).
 */
public class OperationalConfigNotFoundException extends RuntimeException {

    public OperationalConfigNotFoundException() {
        super("No active operational configuration has been applied for this tenant.");
    }
}
