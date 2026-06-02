package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when the {@code X-Consumer-Origin} header is present but contains an
 * unrecognised value.
 *
 * <p>Maps to HTTP 400. A missing header is not an error — the controller defaults
 * to {@code SYSTEM}. Only a header that is present but unparseable triggers this
 * exception (F3 verify finding).</p>
 *
 * <p>Spec: EUDISTACK-407 F3 (verify finding).</p>
 */
public class InvalidConsumerOriginException extends RuntimeException {

    public InvalidConsumerOriginException(String headerValue) {
        super("X-Consumer-Origin header value is not recognised: " + headerValue);
    }
}
