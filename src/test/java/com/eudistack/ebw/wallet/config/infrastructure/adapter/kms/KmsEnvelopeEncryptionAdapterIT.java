package com.eudistack.ebw.wallet.config.infrastructure.adapter.kms;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import reactor.test.StepVerifier;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.testcontainers.containers.localstack.LocalStackContainer.Service.KMS;

/**
 * Integration test for {@link KmsEnvelopeEncryptionAdapter} (T-5a — EUDISTACK-414, AC-2, AC-5).
 *
 * <p>Uses Testcontainers LocalStack to spin up a real KMS endpoint in-process. The adapter is
 * instantiated directly (no Spring context) against the LocalStack endpoint, following the
 * explicit-wiring pattern used by production {@code OperationalConfigBeans}.
 *
 * <p>Test cases:
 * <ul>
 *   <li>TC-1: {@code verifyCmkAccessible} with a valid, freshly-minted CMK ARN completes empty.</li>
 *   <li>TC-2: {@code verifyCmkAccessible} with a fictional ARN signals {@link KmsAccessException}.</li>
 *   <li>TC-3: {@code verifyCmkAccessible} with an invalid ARN format signals
 *       {@link KmsAccessException}.</li>
 *   <li>TC-4: {@code unwrap} with valid ciphertext returns the original plaintext bytes
 *       (roundtrip).</li>
 *   <li>TC-5: {@code unwrap} with corrupted ciphertext bytes signals {@link KmsAccessException}.</li>
 *   <li>TC-6: plaintext DEK never appears in any log event during a successful {@code unwrap}
 *       (security invariant AD-S2 / AC-2).</li>
 * </ul>
 *
 * <p>Tagged {@code integration} — runs under {@code ./gradlew integrationTest} (Docker required).
 */
@Testcontainers
@Tag("integration")
class KmsEnvelopeEncryptionAdapterIT {

    @Container
    static final LocalStackContainer LOCALSTACK =
            new LocalStackContainer(DockerImageName.parse("localstack/localstack:3.8.1"))
                    .withServices(KMS);

    private KmsAsyncClient kmsClient;
    private KmsEnvelopeEncryptionAdapter adapter;

    @BeforeEach
    void setUp() {
        kmsClient = KmsAsyncClient.builder()
                .endpointOverride(LOCALSTACK.getEndpointOverride(KMS))
                .region(Region.of(LOCALSTACK.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .build();
        // Generous timeout to avoid flakiness with LocalStack startup overhead.
        adapter = new KmsEnvelopeEncryptionAdapter(kmsClient, Duration.ofSeconds(5));
    }

    // ------------------------------------------------------------------
    // TC-1 — verifyCmkAccessible with a valid ARN completes empty.
    // ------------------------------------------------------------------

    @Test
    void verifyCmkAccessible_validArn_completesEmpty() {
        String arn = mintCmk();

        StepVerifier.create(adapter.verifyCmkAccessible(arn))
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // TC-2 — verifyCmkAccessible with a fictional (non-existent) ARN signals KmsAccessException.
    // ------------------------------------------------------------------

    @Test
    void verifyCmkAccessible_nonExistentArn_emitsKmsAccessException() {
        String fictional = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000099";

        StepVerifier.create(adapter.verifyCmkAccessible(fictional))
                .expectError(KmsAccessException.class)
                .verify();
    }

    // ------------------------------------------------------------------
    // TC-3 — verifyCmkAccessible with an invalid ARN format signals KmsAccessException.
    //
    // LocalStack (like real KMS) rejects malformed key IDs, so the adapter translates the
    // SDK exception to KmsAccessException before emitting it to the subscriber.
    // ------------------------------------------------------------------

    @Test
    void verifyCmkAccessible_invalidArnFormat_emitsKmsAccessException() {
        StepVerifier.create(adapter.verifyCmkAccessible("not-an-arn"))
                .expectError(KmsAccessException.class)
                .verify();
    }

    // ------------------------------------------------------------------
    // TC-4 — unwrap with valid ciphertext returns the original plaintext bytes (roundtrip).
    //
    // Flow: mint CMK → encrypt plaintext with KMS → call adapter.unwrap() → verify bytes match.
    // The adapter only needs kms:Decrypt (IAM constraint AD-S3); we use the SDK directly here
    // to call kms:Encrypt to produce the ciphertext (mimicking the offline key-wrapping step
    // that the ops runbook performs with aws kms generate-data-key).
    // ------------------------------------------------------------------

    @Test
    void unwrap_validCiphertext_returnsPlaintext() {
        String arn = mintCmk();
        byte[] plaintext = "sample-dek-32-bytes-secret-here!".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = kmsClient.encrypt(EncryptRequest.builder()
                        .keyId(arn)
                        .plaintext(SdkBytes.fromByteArray(plaintext))
                        .build())
                .join()
                .ciphertextBlob()
                .asByteArray();

        StepVerifier.create(adapter.unwrap(ciphertext, arn))
                .assertNext(result -> assertThat(Arrays.equals(result, plaintext)).isTrue())
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // TC-5 — unwrap with corrupted ciphertext bytes signals KmsAccessException.
    //
    // KMS rejects the bytes as invalid ciphertext; the adapter wraps the SDK exception.
    // ------------------------------------------------------------------

    @Test
    void unwrap_corruptedCiphertext_emitsKmsAccessException() {
        String arn = mintCmk();
        byte[] corrupted = {1, 2, 3, 4, 5};

        StepVerifier.create(adapter.unwrap(corrupted, arn))
                .expectError(KmsAccessException.class)
                .verify();
    }

    // ------------------------------------------------------------------
    // TC-6 — plaintext DEK is never logged during a successful unwrap (AD-S2 / AC-2).
    //
    // Wires a Logback ListAppender to KmsEnvelopeEncryptionAdapter's logger BEFORE calling
    // unwrap. After unwrap completes, iterates all captured log events and asserts that none
    // contains the plaintext in HEX or Base64 representation.
    // ------------------------------------------------------------------

    @Test
    void unwrap_neverLogsPlaintext() {
        String arn = mintCmk();
        byte[] plaintext = "never-log-this-dek-value-32bytes".getBytes(StandardCharsets.UTF_8);
        String plaintextHex = bytesToHex(plaintext);
        String plaintextBase64 = Base64.getEncoder().encodeToString(plaintext);

        byte[] ciphertext = kmsClient.encrypt(EncryptRequest.builder()
                        .keyId(arn)
                        .plaintext(SdkBytes.fromByteArray(plaintext))
                        .build())
                .join()
                .ciphertextBlob()
                .asByteArray();

        // Wire the ListAppender to the adapter's SLF4J logger before the call.
        Logger adapterLogger = (Logger) LoggerFactory.getLogger(KmsEnvelopeEncryptionAdapter.class);
        ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
        listAppender.start();
        adapterLogger.addAppender(listAppender);

        try {
            StepVerifier.create(adapter.unwrap(ciphertext, arn))
                    .assertNext(result -> assertThat(Arrays.equals(result, plaintext)).isTrue())
                    .verifyComplete();

            // Assert no captured log event contains the plaintext in any encoding.
            for (ILoggingEvent event : listAppender.list) {
                String message = event.getFormattedMessage();
                assertThat(message)
                        .as("Log event must not contain plaintext HEX")
                        .doesNotContain(plaintextHex);
                assertThat(message)
                        .as("Log event must not contain plaintext Base64")
                        .doesNotContain(plaintextBase64);
            }
        } finally {
            adapterLogger.detachAppender(listAppender);
        }
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /**
     * Creates a new symmetric CMK in LocalStack and returns its ARN.
     */
    private String mintCmk() {
        return kmsClient.createKey(CreateKeyRequest.builder().build())
                .join()
                .keyMetadata()
                .arn();
    }

    /**
     * Converts a byte array to its uppercase hex string representation.
     * Used to check that plaintext does not appear in logs in hex form.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
