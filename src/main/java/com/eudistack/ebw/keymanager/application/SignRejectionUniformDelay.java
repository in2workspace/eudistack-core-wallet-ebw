package com.eudistack.ebw.keymanager.application;

import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Provides the uniform delay applied to all opaque rejection paths.
 *
 * <p>Per ADR-025, rejected signing requests MUST return at the same time as successful
 * requests to prevent timing-based enumeration. This bean encapsulates the delay duration
 * so it can be configured externally ({@code keymanager.sign.opaque-rejection-delay-millis})
 * and tuned without redeployment.</p>
 *
 * <p>The default value ({@value DEFAULT_DELAY_MILLIS} ms) approximates the p50 of a warm
 * signing path. It MUST be calibrated empirically in STG before production deployment
 * (see NFR-S-407-03, AD-407-2). The CI test {@code OpaqueRejectionConstantTimeIT} validates
 * the shape of the delay without relying on wall-clock values.</p>
 *
 * <p>Usage: apply via {@code .delayUntil(ignored -> rejectionDelay.apply())} in the
 * rejection branch of the use case Mono chain.</p>
 *
 * <p>Spec: EUDISTACK-407 AC-06, ES-02, ADR-025, AD-407-2, NFR-S-407-03.</p>
 */
public class SignRejectionUniformDelay {

    public static final long DEFAULT_DELAY_MILLIS = 80L;

    private final Duration delay;

    /**
     * @param delayMillis configured delay in milliseconds; must be positive
     */
    public SignRejectionUniformDelay(long delayMillis) {
        if (delayMillis <= 0) {
            throw new IllegalArgumentException(
                    "opaque-rejection-delay-millis must be positive, got: " + delayMillis);
        }
        this.delay = Duration.ofMillis(delayMillis);
    }

    /**
     * Returns a {@code Mono<Void>} that completes after the configured delay.
     * Used in {@code .delayUntil(...)} on rejection paths.
     */
    public Mono<Void> apply() {
        return Mono.delay(delay).then();
    }

    /** Returns the configured delay duration (for testing). */
    public Duration getDelay() {
        return delay;
    }
}
