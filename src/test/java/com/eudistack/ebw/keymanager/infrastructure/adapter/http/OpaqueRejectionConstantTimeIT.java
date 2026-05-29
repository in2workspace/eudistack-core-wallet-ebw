package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.keymanager.application.SignRejectionUniformDelay;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;

/**
 * Validates the shape of the opaque rejection delay (ADR-025, AD-407-2, NFR-S-407-03).
 *
 * <p>Uses {@link StepVerifier#withVirtualTime} to verify that:
 * <ul>
 *   <li>The rejection delay completes after the configured duration.</li>
 *   <li>The rejection delay does NOT complete before the configured duration.</li>
 * </ul>
 *
 * <p>This test does NOT measure wall-clock timing. The concrete p95 comparison
 * ({@code |p95(ok) - p95(rejected)| < 50 ms}) is validated by k6 in STG.</p>
 *
 * <p>Covers: EUDISTACK-407 AC-06, ES-02, NFR-S-407-03.</p>
 */
class OpaqueRejectionConstantTimeIT {

    @Test
    void apply_delayCompletesAfterConfiguredDuration() {
        // Given
        long delayMs = 80L;
        SignRejectionUniformDelay delay = new SignRejectionUniformDelay(delayMs);

        // When / Then — using virtual time to avoid real wall-clock dependency in CI
        StepVerifier.withVirtualTime(delay::apply)
                .expectSubscription()
                .expectNoEvent(Duration.ofMillis(delayMs - 1))
                .thenAwait(Duration.ofMillis(2))
                .verifyComplete();
    }

    @Test
    void apply_delayDoesNotCompleteBeforeConfiguredDuration() {
        // Given
        long delayMs = 200L;
        SignRejectionUniformDelay delay = new SignRejectionUniformDelay(delayMs);

        StepVerifier.withVirtualTime(delay::apply)
                .expectSubscription()
                .expectNoEvent(Duration.ofMillis(delayMs - 10))
                .thenAwait(Duration.ofMillis(20))
                .verifyComplete();
    }

    @Test
    void apply_eachCallIsIndependent() {
        // Given — each apply() call creates a new Mono.delay
        SignRejectionUniformDelay delay = new SignRejectionUniformDelay(50L);

        Mono<Void> combined = delay.apply().then(delay.apply());

        StepVerifier.withVirtualTime(() -> combined)
                .expectSubscription()
                .expectNoEvent(Duration.ofMillis(40))
                .thenAwait(Duration.ofMillis(120))
                .verifyComplete();
    }

    @Test
    void constructor_zeroDelay_throws() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> new SignRejectionUniformDelay(0L))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getDelay_returnsConfiguredDuration() {
        SignRejectionUniformDelay delay = new SignRejectionUniformDelay(120L);
        org.assertj.core.api.Assertions.assertThat(delay.getDelay())
                .isEqualTo(Duration.ofMillis(120));
    }
}
