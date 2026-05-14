package com.eudistack.ebw.wallet.config.infrastructure.adapter.kms;

import com.eudistack.ebw.wallet.config.domain.port.EnvelopeEncryptionPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.KmsException;

import java.time.Duration;
import java.util.concurrent.TimeoutException;

/**
 * AWS KMS implementation of {@link EnvelopeEncryptionPort}.
 *
 * <p>All calls are async (non-blocking): the adapter wraps the {@link KmsAsyncClient}
 * {@link java.util.concurrent.CompletableFuture} return type in a {@link Mono} using
 * {@link Mono#fromFuture(java.util.function.Supplier)}. The supplier form (lambda) is used
 * so the future is created lazily — one future per subscription, avoiding shared state
 * between concurrent subscribers.
 *
 * <h2>Security invariants (non-negotiable)</h2>
 * <ul>
 *   <li>The plaintext DEK returned by {@link #unwrap} is NEVER logged at any level.
 *       The {@code doOnError} and {@code onErrorMap} operators only log/emit the error context,
 *       not the response payload.</li>
 *   <li>The CMK ARN is NOT included in any log message (prevents CloudTrail correlation
 *       from log aggregators — AD-S3).</li>
 *   <li>All AWS SDK exceptions are translated to {@link KmsAccessException} with a functional
 *       message built by {@link #functionalMessage(Throwable)}. Raw AWS error bodies are
 *       never surfaced to callers (AD-S2).</li>
 *   <li>The unwrapped DEK byte array is defensively copied before emission (clone) so the
 *       SDK's internal buffer cannot be mutated or zeroed by the caller's actions on the
 *       emitted reference.</li>
 * </ul>
 *
 * <h2>IAM scope (AD-S3)</h2>
 * The EBW task role requires ONLY {@code kms:DescribeKey} (for probe) and {@code kms:Decrypt}
 * (for unwrap) on the CMK. {@code kms:Encrypt} and {@code kms:GenerateDataKey} are NOT needed
 * and MUST NOT be granted (IaC enforced in Task 18).
 *
 * <h2>Wiring</h2>
 * This class is NOT annotated with {@code @Component}. It follows the same explicit-wiring
 * pattern as {@code WalletTenantConfigR2dbcAdapter} and {@code OperationalConfigAuditR2dbcAdapter}:
 * {@code OperationalConfigBeans} (Task 9) constructs the instance and exposes it as a Spring bean.
 */
public class KmsEnvelopeEncryptionAdapter implements EnvelopeEncryptionPort {

    private static final Logger log = LoggerFactory.getLogger(KmsEnvelopeEncryptionAdapter.class);

    private final KmsAsyncClient kmsAsyncClient;
    private final Duration probeTimeout;

    /**
     * Constructs the adapter.
     *
     * @param kmsAsyncClient the AWS SDK v2 async KMS client (provisioned by
     *                       {@link KmsClientConfig#kmsAsyncClient()})
     * @param probeTimeout   maximum time to wait for any KMS call before signalling a timeout
     *                       error; configured from {@code wallet-ebw.probe.timeout-ms} in
     *                       {@code OperationalConfigBeans} (Task 9)
     */
    public KmsEnvelopeEncryptionAdapter(KmsAsyncClient kmsAsyncClient, Duration probeTimeout) {
        this.kmsAsyncClient = kmsAsyncClient;
        this.probeTimeout = probeTimeout;
    }

    /**
     * Verifies that the CMK identified by {@code cmkArn} is accessible to the EBW task role.
     *
     * <p>Calls {@code kms:DescribeKey(cmkArn)}. Completes empty ({@code Mono<Void>}) if the key
     * exists, is in {@code ENABLED} state, and the IAM policy allows the call. Signals a
     * {@link KmsAccessException} on any failure including timeout.
     *
     * <p>The CMK ARN is not logged. The warn message only contains a functional description of
     * the failure (class name + AWS error code if available).
     *
     * @param cmkArn the AWS KMS ARN of the CMK to verify
     * @return {@link Mono} that completes empty on success, or terminates with
     *         {@link KmsAccessException} on any failure
     */
    @Override
    public Mono<Void> verifyCmkAccessible(String cmkArn) {
        return Mono.fromFuture(() -> kmsAsyncClient.describeKey(req -> req.keyId(cmkArn)))
                .timeout(probeTimeout)
                .doOnError(e -> log.warn(
                        "kms.probe outcome=fail reason={}", functionalMessage(e)))
                .onErrorMap(
                        e -> !(e instanceof KmsAccessException),
                        e -> new KmsAccessException("CMK probe failed: " + functionalMessage(e), e))
                .then();
    }

    /**
     * Unwraps (decrypts) a wrapped data-encryption key (DEK) using the specified CMK.
     *
     * <p>Calls {@code kms:Decrypt(wrappedDek, cmkArn)}. Returns the plaintext DEK bytes as a
     * defensive copy — the caller is responsible for zeroing the array after use to minimise
     * the plaintext lifetime in memory.
     *
     * <p><strong>CRITICAL:</strong> the plaintext DEK is NEVER logged at any level.
     * The {@code doOnError} operator only logs the functional error message, not the response.
     *
     * @param wrappedDek the ciphertext DEK (the {@code CiphertextBlob} from a prior
     *                   {@code kms:GenerateDataKey} call)
     * @param cmkArn     the ARN of the CMK that was used to wrap the DEK
     * @return {@link Mono} emitting the plaintext DEK bytes (defensive copy), or terminating
     *         with {@link KmsAccessException} on any failure
     */
    @Override
    public Mono<byte[]> unwrap(byte[] wrappedDek, String cmkArn) {
        return Mono.fromFuture(() -> kmsAsyncClient.decrypt(req -> req
                        .ciphertextBlob(SdkBytes.fromByteArray(wrappedDek))
                        .keyId(cmkArn)))
                .timeout(probeTimeout)
                .map(response -> response.plaintext().asByteArray().clone())
                .doOnError(e -> log.warn(
                        "kms.unwrap outcome=fail reason={}", functionalMessage(e)))
                .onErrorMap(
                        e -> !(e instanceof KmsAccessException),
                        e -> new KmsAccessException("KMS unwrap failed: " + functionalMessage(e), e));
    }

    // --- Private helpers ---

    /**
     * Builds a functional, safe error message from the given throwable.
     *
     * <p>Rules:
     * <ul>
     *   <li>{@link TimeoutException}: returns {@code "probe timed out"}.</li>
     *   <li>{@link KmsException} (AWS SDK): returns the simple class name plus the AWS error code
     *       from {@link KmsException#awsErrorDetails()} if available.</li>
     *   <li>Any other throwable: returns the simple class name only.</li>
     * </ul>
     *
     * <p>The ARN is never included. The full exception message (which may contain AWS response
     * detail) is never included. This keeps the output safe for audit events and Problem Details
     * responses (AC-4d, AD-S2).
     *
     * @param e the throwable to describe
     * @return a short functional string, never {@code null}
     */
    static String functionalMessage(Throwable e) {
        if (e instanceof TimeoutException) {
            return "probe timed out";
        }
        if (e instanceof KmsException kmsEx) {
            String errorCode = (kmsEx.awsErrorDetails() != null)
                    ? kmsEx.awsErrorDetails().errorCode()
                    : null;
            if (errorCode != null && !errorCode.isBlank()) {
                return kmsEx.getClass().getSimpleName() + ": " + errorCode;
            }
            return kmsEx.getClass().getSimpleName();
        }
        return e.getClass().getSimpleName();
    }
}
