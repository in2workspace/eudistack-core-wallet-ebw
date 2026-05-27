package com.eudistack.ebw.keymanager.infrastructure.adapter.audit;

import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsAsyncClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.CreateLogGroupRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.CreateLogStreamRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.GetLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.OutputLogEvent;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test verifying the SHA-256 hash chain between consecutive audit batches
 * (ADR-062, no-KMS variant).
 *
 * <p>The test emits events across two separate drain cycles and asserts:
 * <ul>
 *   <li>Batch 1: {@code previous_batch_hash} = {@code "0".repeat(64)} (zero seed)</li>
 *   <li>Batch 2: {@code previous_batch_hash} = {@code batch_hash} of batch 1</li>
 *   <li>Each {@code batch_hash} is the SHA-256 of the canonical JSON
 *       (batch fields sorted lexicographically, excluding {@code batch_hash} itself)</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-119 AC-07, ADR-062 §3.2 (hash chain integrity).</p>
 */
@Tag("integration")
@Testcontainers
class KeyAuditBatchHashChainIT {

    private static final String LOG_GROUP = "/eudistack/audit/wallet-ebw/hashchain-test";
    private static final String ZERO_HASH = "0".repeat(64);

    @Container
    static final LocalStackContainer localStack =
            new LocalStackContainer(DockerImageName.parse("localstack/localstack:3"))
                    .withServices(LocalStackContainer.Service.CLOUDWATCHLOGS);

    private CloudWatchLogsAsyncClient logsClient;
    private ObjectMapper objectMapper;
    private String logStreamName;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        logStreamName = "hashchain-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        logsClient = CloudWatchLogsAsyncClient.builder()
                .endpointOverride(localStack.getEndpointOverride(LocalStackContainer.Service.CLOUDWATCHLOGS))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .region(Region.of(localStack.getRegion()))
                .build();

        logsClient.createLogGroup(CreateLogGroupRequest.builder()
                .logGroupName(LOG_GROUP)
                .build()).join();
        logsClient.createLogStream(CreateLogStreamRequest.builder()
                .logGroupName(LOG_GROUP)
                .logStreamName(logStreamName)
                .build()).join();
    }

    // -------------------------------------------------------------------------
    // ADR-062 §3.2 — hash chain links batch N+1 to batch N
    // -------------------------------------------------------------------------

    @Test
    void twoBatches_hashChainLinksSecondBatchToFirst() throws Exception {
        KeyAuditCloudWatchAdapter adapter = new KeyAuditCloudWatchAdapter(
                LOG_GROUP, objectMapper, logsClient, logStreamName);

        try {
            // Batch 1: emit one event and drain
            adapter.emit(makeEvent("cred-chain-1")).block();
            adapter.triggerDrainForTest().block();

            // Batch 2: emit a second event and drain
            adapter.emit(makeEvent("cred-chain-2")).block();
            adapter.triggerDrainForTest().block();

            List<OutputLogEvent> logEvents = logsClient.getLogEvents(GetLogEventsRequest.builder()
                    .logGroupName(LOG_GROUP)
                    .logStreamName(logStreamName)
                    .startFromHead(true)
                    .build()).join().events();

            assertThat(logEvents)
                    .as("two batches must be published (one per drain cycle)")
                    .hasSize(2);

            @SuppressWarnings("unchecked")
            Map<String, Object> batch1 = objectMapper.readValue(logEvents.get(0).message(), Map.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> batch2 = objectMapper.readValue(logEvents.get(1).message(), Map.class);

            // Batch 1 starts the chain with the zero seed
            assertThat(batch1.get("previous_batch_hash"))
                    .as("first batch previous_batch_hash must be zero-seed (ADR-062 §3.2)")
                    .isEqualTo(ZERO_HASH);

            // Batch 2's previous_batch_hash must equal batch 1's batch_hash
            String batch1Hash = (String) batch1.get("batch_hash");
            String batch2PrevHash = (String) batch2.get("previous_batch_hash");

            assertThat(batch2PrevHash)
                    .as("batch 2 previous_batch_hash must equal batch 1 batch_hash (ADR-062 §3.2)")
                    .isEqualTo(batch1Hash);

            // Verify batch_hash of batch 1 = SHA-256 of its canonical JSON
            // (canonical JSON = TreeMap of batch fields EXCLUDING batch_hash, then serialised)
            TreeMap<String, Object> canonicalBatch1 = new TreeMap<>();
            canonicalBatch1.put("batch_id", batch1.get("batch_id"));
            canonicalBatch1.put("events", batch1.get("events"));
            canonicalBatch1.put("previous_batch_hash", batch1.get("previous_batch_hash"));
            canonicalBatch1.put("published_at", batch1.get("published_at"));

            byte[] canonicalBytes = objectMapper.writeValueAsBytes(canonicalBatch1);
            byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(canonicalBytes);
            String recomputedHash = HexFormat.of().formatHex(digestBytes);

            assertThat(batch1Hash)
                    .as("batch_hash must equal SHA-256(canonical JSON excl. batch_hash) — ADR-062 §3.2")
                    .isEqualTo(recomputedHash);

        } finally {
            adapter.destroy();
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private KeyAuditEvent makeEvent(String credentialId) {
        return new KeyAuditEvent(
                KeyAuditEvent.KeyAuditEventType.KEY_GENERATED,
                "chain-tenant",
                UUID.randomUUID().toString(),
                credentialId,
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                "jkt-chain-" + credentialId,
                Instant.now(),
                UUID.randomUUID().toString()
        );
    }
}