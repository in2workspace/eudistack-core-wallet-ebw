package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when a key access request must be rejected with an opaque response.
 *
 * <p>Per ADR-025, the HTTP response for any rejection in the signing path MUST be opaque:
 * identical body, identical headers, and uniform timing (achieved via
 * {@code SignRejectionUniformDelay}). The {@code internalReason} is ONLY used for audit
 * logging — it is never serialised into the HTTP response.</p>
 *
 * <p>Rejection scenarios that produce this exception:
 * <ul>
 *   <li>Key not found (keyId does not exist for the given tenant)</li>
 *   <li>Key revoked ({@code revoked_at IS NOT NULL} — EC-01)</li>
 *   <li>Cross-tenant attempt (tenant isolation violation)</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-407 AC-06, ES-02, ADR-025.</p>
 */
public class KeyAccessDeniedException extends RuntimeException {

    private final String internalReason;

    /**
     * Constructs a denial with a generic reason (no internal detail).
     * Maintained for backward-compatibility with US-02 callers.
     */
    public KeyAccessDeniedException() {
        super("Key access denied");
        this.internalReason = "UNSPECIFIED";
    }

    /**
     * Constructs a denial with an internal reason for audit logging.
     *
     * <p>The {@code internalReason} is written to the audit event ({@code reason} field) and
     * is visible to the Security Lead via Dominio D2 queries. It is NEVER included in the
     * HTTP response (that response is always the opaque {@code { "error": "KeyAccessDenied" }}).
     *
     * @param internalReason machine-readable sub-cause; recommended values:
     *                       {@code KEY_NOT_FOUND}, {@code KEY_REVOKED}, {@code CROSS_TENANT}
     */
    public KeyAccessDeniedException(String internalReason) {
        super("Key access denied");
        this.internalReason = (internalReason != null) ? internalReason : "UNSPECIFIED";
    }

    /**
     * Returns the internal reason for audit purposes.
     * MUST NOT be included in HTTP responses.
     */
    public String getInternalReason() {
        return internalReason;
    }
}
