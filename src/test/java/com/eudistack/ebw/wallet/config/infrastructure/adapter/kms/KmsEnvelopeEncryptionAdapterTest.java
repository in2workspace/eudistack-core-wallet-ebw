package com.eudistack.ebw.wallet.config.infrastructure.adapter.kms;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Pure unit test for {@link KmsEnvelopeEncryptionAdapter} — no Docker, no Testcontainers.
 *
 * <p>Uses Mockito to control {@link KmsAsyncClient} behavior and {@code reactor-test}
 * {@link StepVerifier} for reactive assertions.
 *
 * <p>Test case:
 * <ul>
 *   <li>TC-1: when the KMS call takes longer than the configured probe timeout (50 ms),
 *       {@code verifyCmkAccessible} signals {@link KmsAccessException} whose message
 *       contains {@code "timed out"}. This validates that Reactor's {@code Mono.timeout()} is
 *       wired correctly and that the resulting {@code TimeoutException} is translated
 *       via {@link KmsEnvelopeEncryptionAdapter#functionalMessage(Throwable)} to the
 *       right {@link KmsAccessException} wrapper.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class KmsEnvelopeEncryptionAdapterTest {

    @Mock
    private KmsAsyncClient kmsClient;

    // ------------------------------------------------------------------
    // TC-1 — When KMS takes longer than probeTimeout, KmsAccessException is signalled.
    //
    // A CompletableFuture that is never completed simulates a slow KMS endpoint.
    // The adapter calls kmsAsyncClient.describeKey(Consumer<Builder>) which is a default
    // method on the KmsAsyncClient interface delegating to describeKey(DescribeKeyRequest).
    // We stub both overloads with lenient() to avoid Mockito strict-stubbing complaints
    // from whichever overload the SDK wires through.
    //
    // The adapter's Mono.fromFuture(...).timeout(50ms) triggers TimeoutException, which
    // functionalMessage() maps to "probe timed out", and the onErrorMap wraps it as
    // KmsAccessException with that message.
    // ------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void verifyCmkAccessible_kmsTakesLongerThanTimeout_emitsKmsAccessException() {
        // A future that never completes — simulates an unresponsive KMS endpoint.
        CompletableFuture<DescribeKeyResponse> slowFuture = new CompletableFuture<>();

        // Stub both the request-based and consumer-based overloads with lenient() so
        // whichever the AWS SDK delegates to is covered without strict-stubbing violations.
        lenient().when(kmsClient.describeKey(any(software.amazon.awssdk.services.kms.model.DescribeKeyRequest.class)))
                .thenReturn(slowFuture);
        lenient().when(kmsClient.describeKey(any(Consumer.class)))
                .thenReturn(slowFuture);

        // 50 ms probe timeout — much shorter than any real network call.
        KmsEnvelopeEncryptionAdapter adapter =
                new KmsEnvelopeEncryptionAdapter(kmsClient, Duration.ofMillis(50));

        StepVerifier.create(adapter.verifyCmkAccessible(
                        "arn:aws:kms:eu-west-1:123456789012:key/test-timeout-key"))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(KmsAccessException.class);
                    assertThat(error.getMessage()).contains("timed out");
                })
                .verify(Duration.ofSeconds(5));
    }
}
