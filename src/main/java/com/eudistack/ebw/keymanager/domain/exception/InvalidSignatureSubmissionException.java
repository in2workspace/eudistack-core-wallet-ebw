package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when the hybrid (Passkey PRF) submit request is structurally invalid or
 * references an unknown / expired {@code correlation_id}.
 *
 * <p>Conditions:
 * <ul>
 *   <li>The {@code correlation_id} does not match any active {@code prepareSign} session
 *       (expired, never issued, or already finalised with a conflicting result).</li>
 *   <li>The {@code signature} field is not a valid base64url-encoded byte sequence.</li>
 * </ul>
 *
 * <p>Maps to HTTP 400 {@code invalid_request} in {@code HybridKeyManagerExceptionHandler}.
 * The message MUST NOT include {@code prf_salt}, wrapped-blob content, or the holder private
 * key material (NFR-S-536-03).</p>
 *
 * <p>Spec: EUDISTACK-536 ES-01; architecture.md §8.3 (error catalogue).</p>
 */
public class InvalidSignatureSubmissionException extends RuntimeException {

    public InvalidSignatureSubmissionException(String reason) {
        super(reason);
    }
}
