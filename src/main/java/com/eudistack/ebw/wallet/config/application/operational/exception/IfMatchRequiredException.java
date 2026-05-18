package com.eudistack.ebw.wallet.config.application.operational.exception;

/**
 * Thrown by {@code OperationalConfigController} when a PUT request is missing the
 * required {@code If-Match} header.
 *
 * <p>Maps to HTTP {@code 428 Precondition Required} via
 * {@link com.eudistack.ebw.wallet.config.infrastructure.controller.exception.OperationalConfigExceptionHandler}.
 */
public class IfMatchRequiredException extends RuntimeException {

    public IfMatchRequiredException() {
        super("PUT requires an If-Match header with the current version (e.g. If-Match: \"0\")");
    }
}
