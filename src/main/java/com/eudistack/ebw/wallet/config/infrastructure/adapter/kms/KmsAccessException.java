package com.eudistack.ebw.wallet.config.infrastructure.adapter.kms;

/**
 * Thrown by {@link KmsEnvelopeEncryptionAdapter} when an AWS KMS call fails due to
 * permission denial, key unavailability, timeout, or any other infrastructure error.
 *
 * <p>This exception acts as the infrastructure-layer translation of all KMS SDK exceptions into
 * a single functional signal that the application layer can handle without depending on the
 * AWS SDK exception hierarchy (AD-S2 in tech-design §3.5).
 *
 * <p>Maps to HTTP {@code 424 Failed Dependency} in the controller layer exception handler
 * (Task 8). The message is functional and safe for inclusion in {@code Problem Details}
 * (RFC 9457) — it never contains raw AWS error response bodies or ARN string values.
 *
 * <p>No Spring annotations: this is a plain infrastructure exception, not a managed bean.
 * Placement in {@code infrastructure/adapter/kms/} keeps the domain port ({@link
 * com.eudistack.ebw.wallet.config.domain.port.EnvelopeEncryptionPort}) free of any
 * infrastructure type references.
 */
public class KmsAccessException extends RuntimeException {

    /**
     * Constructs a {@code KmsAccessException} with the given functional message.
     *
     * @param message a short, safe description of the failure; must not contain raw AWS response
     *                bodies, ARN values, or secret material
     */
    public KmsAccessException(String message) {
        super(message);
    }

    /**
     * Constructs a {@code KmsAccessException} wrapping a lower-level cause.
     *
     * @param message a short, safe description of the failure
     * @param cause   the underlying exception (e.g. {@code KmsException}, {@code TimeoutException})
     */
    public KmsAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}
