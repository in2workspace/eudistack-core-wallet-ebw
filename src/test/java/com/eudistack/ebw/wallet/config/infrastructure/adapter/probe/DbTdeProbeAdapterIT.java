package com.eudistack.ebw.wallet.config.infrastructure.adapter.probe;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.DbTdeOperationalConfig;
import com.eudistack.ebw.wallet.config.domain.model.probe.ProbeResult;
import com.eudistack.ebw.wallet.config.domain.port.OperationalConfigPort;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.kms.KmsEnvelopeEncryptionAdapter;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testcontainers.containers.localstack.LocalStackContainer.Service.KMS;

/**
 * Integration test for {@link DbTdeProbeAdapter} (T-5b — EUDISTACK-414, AC-2, AC-5, E-4, E-14).
 *
 * <p>Uses Testcontainers LocalStack for a real KMS endpoint. {@link OperationalConfigPort} is
 * Mockito-mocked to isolate the probe logic from the R2DBC layer. The adapter and its dependencies
 * are wired explicitly (no Spring context), mirroring {@code OperationalConfigBeans} in production.
 * {@link ObservationRegistry#NOOP} is used so no OTEL backend is required.
 *
 * <p>Test cases:
 * <ul>
 *   <li>TC-1: happy path — valid CMK + {@code canQuerySubtable=true} → {@link ProbeResult.Ok}
 *       with non-negative latency.</li>
 *   <li>TC-2: invalid (fictional) CMK ARN → {@link ProbeResult.Failed} with reason starting
 *       with {@code "kms:"}.</li>
 *   <li>TC-3: valid CMK + {@code canQuerySubtable=false} → {@link ProbeResult.Failed} with
 *       reason {@code "db-tde subtable not accessible"}.</li>
 * </ul>
 *
 * <p>Defense-in-depth case for a non-{@link DbTdeOperationalConfig} input is OMITTED — it is
 * unreachable while the sealed type {@code OperationalConfig} permits only {@code DbTdeOperationalConfig}
 * in this Story. {@code OperationalConfigWriter} (AD-S1) guarantees only DB_TDE reaches this adapter.
 *
 * <p>Tagged {@code integration} — runs under {@code ./gradlew integrationTest} (Docker required).
 */
@Testcontainers
@Tag("integration")
class DbTdeProbeAdapterIT {

    @Container
    static final LocalStackContainer LOCALSTACK =
            new LocalStackContainer(DockerImageName.parse("localstack/localstack:3.8.1"))
                    .withServices(KMS);

    private KmsAsyncClient kmsClient;
    private KmsEnvelopeEncryptionAdapter kmsAdapter;
    private OperationalConfigPort operationalConfigPort;
    private DbTdeProbeAdapter probeAdapter;

    @BeforeEach
    void setUp() {
        kmsClient = KmsAsyncClient.builder()
                .endpointOverride(LOCALSTACK.getEndpointOverride(KMS))
                .region(Region.of(LOCALSTACK.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .build();
        kmsAdapter = new KmsEnvelopeEncryptionAdapter(kmsClient, Duration.ofSeconds(5));
        operationalConfigPort = mock(OperationalConfigPort.class);
        probeAdapter = new DbTdeProbeAdapter(kmsAdapter, operationalConfigPort,
                ObservationRegistry.NOOP);
    }

    // ------------------------------------------------------------------
    // TC-1 — Happy path: valid CMK + canQuerySubtable=true → ProbeResult.Ok.
    // ------------------------------------------------------------------

    @Test
    void probe_validConfig_returnsOk() {
        String arn = mintCmk();
        DbTdeOperationalConfig config = new DbTdeOperationalConfig(arn,
                new byte[]{1, 2, 3, 4}, "AES-256-GCM");

        when(operationalConfigPort.canQuerySubtable(KeyManager.DB_TDE))
                .thenReturn(Mono.just(true));

        StepVerifier.create(probeAdapter.probe(config))
                .assertNext(result -> {
                    assertThat(result).isInstanceOf(ProbeResult.Ok.class);
                    assertThat(((ProbeResult.Ok) result).latencyMs()).isGreaterThanOrEqualTo(0);
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // TC-2 — Fictional CMK ARN → ProbeResult.Failed with "kms:" prefix.
    // ------------------------------------------------------------------

    @Test
    void probe_invalidCmk_returnsFailed() {
        String fictionalArn =
                "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000099";
        DbTdeOperationalConfig config = new DbTdeOperationalConfig(fictionalArn,
                new byte[]{1, 2, 3, 4}, "AES-256-GCM");

        when(operationalConfigPort.canQuerySubtable(KeyManager.DB_TDE))
                .thenReturn(Mono.just(true));

        StepVerifier.create(probeAdapter.probe(config))
                .assertNext(result -> {
                    assertThat(result).isInstanceOf(ProbeResult.Failed.class);
                    assertThat(((ProbeResult.Failed) result).reason()).startsWith("kms:");
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // TC-3 — Valid CMK + canQuerySubtable=false → ProbeResult.Failed("db-tde subtable not accessible").
    // ------------------------------------------------------------------

    @Test
    void probe_canQuerySubtableFalse_returnsFailed() {
        String arn = mintCmk();
        DbTdeOperationalConfig config = new DbTdeOperationalConfig(arn,
                new byte[]{1, 2, 3, 4}, "AES-256-GCM");

        when(operationalConfigPort.canQuerySubtable(KeyManager.DB_TDE))
                .thenReturn(Mono.just(false));

        StepVerifier.create(probeAdapter.probe(config))
                .assertNext(result -> {
                    assertThat(result).isInstanceOf(ProbeResult.Failed.class);
                    assertThat(((ProbeResult.Failed) result).reason())
                            .isEqualTo("db-tde subtable not accessible");
                })
                .verifyComplete();
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
}
