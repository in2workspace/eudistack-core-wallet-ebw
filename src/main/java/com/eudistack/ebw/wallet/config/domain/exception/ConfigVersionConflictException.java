package com.eudistack.ebw.wallet.config.domain.exception;

/**
 * Thrown on an optimistic-lock miss: a PUT carried a {@code version} that no longer matches the
 * version stored for the tenant (a concurrent write bumped it).
 *
 * <p>Maps to HTTP 409 Conflict at the controller boundary (RFC 9457 body, similar to
 * {@link ConfigInvariantViolationException}).
 */
public class ConfigVersionConflictException extends RuntimeException {

    private final long expectedVersion;

    public ConfigVersionConflictException(long expectedVersion) {
        super(String.format(
                "optimistic lock failure: expected version %d no longer matches the stored value",
                expectedVersion));
        this.expectedVersion = expectedVersion;
    }

    public long getExpectedVersion() {
        return expectedVersion;
    }
}
