package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when the {@code keyId} path variable cannot be parsed as a valid UUID.
 *
 * <p>This is a consumer programming error (malformed input) and maps to HTTP 400 — distinct
 * from {@link KeyAccessDeniedException} (opaque 401) which requires a syntactically valid
 * but unauthorised key reference.</p>
 *
 * <p>Spec: EUDISTACK-407 W2 (verify finding).</p>
 */
public class InvalidKeyIdFormatException extends RuntimeException {

    public InvalidKeyIdFormatException(String keyId) {
        super("keyId is not a valid UUID: " + keyId);
    }
}
