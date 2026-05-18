package com.eudistack.ebw.wallet.config.domain.port;

import reactor.core.publisher.Mono;

/**
 * Output port — KMS envelope-encryption abstraction for the operational-config plane.
 *
 * <p>Isolates the domain and application layers from the AWS KMS SDK (AD-S2 in
 * tech-design §3.5). Any component that needs to verify CMK accessibility or unwrap a
 * data-encryption key (DEK) calls this port; the implementing adapter
 * ({@code KmsEnvelopeEncryptionAdapter}) translates the call to AWS SDK v2 operations.
 *
 * <h2>Methods declared in this Story</h2>
 * <ul>
 *   <li>{@link #verifyCmkAccessible(String)} — used by {@code DbTdeProbeAdapter} during the
 *       connectivity probe (AC-5d). Calls {@code kms:DescribeKey} to verify that the CMK
 *       identified by the ARN exists, is enabled, and the EBW task role has access to it.
 *       Does not decrypt anything — {@code DescribeKey} is idempotent and cheap.</li>
 *   <li>{@link #unwrap(byte[], String)} — declared forward per tech-design §3.2 note. Not
 *       consumed in US-03: decrypting the wrapped DEK belongs to the downstream column-encryption
 *       consumer (a separate runtime concern). It is declared now so that the port contract is
 *       stable and US-05/06/07 / the column-encryption consumer do not trigger a breaking
 *       change when they need it (AD-S2, YAGNI trade-off documented in tech-design §3.5).</li>
 * </ul>
 *
 * <p>This interface has zero framework or infrastructure imports — it belongs to the domain layer.
 * No AWS SDK types appear in any signature. The implementing adapter lives in
 * {@code infrastructure/adapter/kms}.
 */
public interface EnvelopeEncryptionPort {

    /**
     * Verifies that the KMS Customer Master Key (CMK) identified by {@code cmkArn} is accessible
     * to the EBW runtime.
     *
     * <p>Implementation: calls {@code kms:DescribeKey(cmkArn)}. Returns successfully if and only
     * if the key exists, is in {@code ENABLED} state, and the EBW task role's IAM policy allows
     * the call. Translates all AWS SDK exceptions to a functional error signal so that callers
     * remain decoupled from the AWS SDK exception hierarchy.
     *
     * <p>Timeout: 5 seconds (configurable via {@code wallet-ebw.probe.timeout-ms} — E-14).
     * A timeout is treated as a failure: the {@link Mono} terminates with an error that
     * {@code DbTdeProbeAdapter} maps to {@code ProbeResult.Failed("kms describe-key timeout")}.
     *
     * <p>IAM note: the EBW task role requires only {@code kms:DescribeKey} and {@code kms:Decrypt}
     * on the CMK — NOT {@code kms:Encrypt} or {@code kms:GenerateDataKey} (AD-S3).
     *
     * @param cmkArn the AWS KMS ARN of the CMK to verify (e.g.
     *               {@code arn:aws:kms:eu-west-1:123456789012:key/mrk-...})
     * @return a {@link Mono} that completes empty ({@code Mono<Void>}) when the CMK is
     *         accessible, or terminates with an error (e.g. {@code KmsAccessException}) when
     *         the CMK is not accessible, does not exist, is disabled, or the call times out
     */
    Mono<Void> verifyCmkAccessible(String cmkArn);

    /**
     * Unwraps (decrypts) a wrapped data-encryption key (DEK) using the specified CMK.
     *
     * <p>Implementation: calls {@code kms:Decrypt(wrappedDek, cmkArn)}. Returns the plaintext
     * DEK bytes. The caller is responsible for zeroing the returned array after use to minimize
     * the plaintext's lifetime in memory.
     *
     * <p><b>Not consumed in US-03.</b> Declared now to avoid a port-breaking change when the
     * downstream column-encryption consumer (a future Story) needs it. The
     * {@code KmsEnvelopeEncryptionAdapter} implements the method so the contract test
     * ({@code KmsEnvelopeEncryptionAdapterIT}) can verify the full adapter surface (T-5).
     *
     * <p>IAM note: the EBW task role requires {@code kms:Decrypt} on the CMK to call this method.
     *
     * @param wrappedDek the ciphertext DEK produced by a prior {@code kms:GenerateDataKey} call
     *                   (the {@code CiphertextBlob} field, not the plaintext)
     * @param cmkArn     the AWS KMS ARN of the CMK that was used to wrap the DEK
     * @return a {@link Mono} emitting the plaintext DEK bytes; never emits {@code Mono.empty()}.
     *         Terminates with an error (e.g. {@code KmsAccessException}) if decryption fails.
     */
    Mono<byte[]> unwrap(byte[] wrappedDek, String cmkArn);
}
