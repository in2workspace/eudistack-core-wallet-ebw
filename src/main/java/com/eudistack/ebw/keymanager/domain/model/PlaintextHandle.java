package com.eudistack.ebw.keymanager.domain.model;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A generic handle that wraps a sensitive plaintext value and provides a deterministic
 * zeroise-on-close contract.
 *
 * <p>Callers are expected to use a try-with-resources block to guarantee that the zeroizer
 * runs even in the presence of exceptions. The zeroizer is idempotent — a second call to
 * {@link #close()} is a no-op.</p>
 *
 * <p>Security: {@link #toString()} always returns {@code "PlaintextHandle[REDACTED]"} to
 * prevent accidental exposure of the wrapped value in logs or exception messages
 * (NFR-SEC-03, R-119-1).</p>
 *
 * <p>Spec: EUDISTACK-119 (key hygiene requirement), ADR-099.</p>
 *
 * @param <T> the type of the sensitive value
 */
public final class PlaintextHandle<T> implements AutoCloseable {

    private final T value;
    private final Runnable zeroizer;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * Creates a new handle wrapping the given value.
     *
     * @param value    the sensitive value to protect; must not be null
     * @param zeroizer callback invoked exactly once on {@link #close()} to zero the
     *                 underlying secret material; must not be null
     */
    public PlaintextHandle(T value, Runnable zeroizer) {
        if (value == null) {
            throw new IllegalArgumentException("PlaintextHandle value must not be null");
        }
        if (zeroizer == null) {
            throw new IllegalArgumentException("PlaintextHandle zeroizer must not be null");
        }
        this.value = value;
        this.zeroizer = zeroizer;
    }

    /**
     * Returns the wrapped sensitive value.
     *
     * @return the value
     */
    public T value() {
        return value;
    }

    /**
     * Invokes the zeroizer exactly once. Subsequent calls are no-ops.
     */
    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            zeroizer.run();
        }
    }

    /**
     * Always returns a redacted representation — never exposes the wrapped value.
     *
     * @return {@code "PlaintextHandle[REDACTED]"}
     */
    @Override
    public String toString() {
        return "PlaintextHandle[REDACTED]";
    }
}