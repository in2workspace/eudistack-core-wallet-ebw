package com.eudistack.ebw.keymanager.domain.exception;

import java.util.List;

/**
 * Thrown when no overlap is found between the requested JWS algorithms and the supported ones.
 *
 * <p>The message includes algorithm names only — no key material is ever included.
 * This exception drives the 400 response in the HTTP layer per EUDISTACK-119 AC-05.</p>
 *
 * <p>Spec: OID4VCI 1.0 §7.2.1 (proof JWT header {@code alg}), ADR-024 (algorithm negotiation),
 * EUDISTACK-119 AC-05.</p>
 */
public class UnsupportedJwsAlgorithmException extends RuntimeException {

    public UnsupportedJwsAlgorithmException(List<String> requestedAlgs, List<String> supportedAlgs) {
        super("No supported JWS algorithm found. Requested: " + requestedAlgs + ", Supported: " + supportedAlgs);
    }
}