package com.eudistack.ebw.keymanager.infrastructure.adapter.audit;

import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.fasterxml.jackson.core.type.TypeReference;
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
import software.amazon.awssdk.services.cloudwatchlogs.model.ResourceAlreadyExistsException;
import software.amazon.awssdk.services.cloudwatchlogs.model.GetLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.OutputLogEvent;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for {@link KeyAuditCloudWatchAdapter}: verifies the shape of the
 * published audit event and that it contains no private key material (AC-07).
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-07 — event fields: type, tenantId, holderId, credentialId, format, algorithm,
 *       jkt, timestamp, correlation_id present in the batch</li>
 *   <li>AC-07 — event does NOT contain private key material (no "private_key", no
 *       "key_bytes" fields)</li>
 *   <li>AC-07 — first batch has previous_batch_hash = "0".repeat(64) (zero-seed)</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-119 AC-07, NFR-S-119-03, ADR-062 (no-KMS variant), ADR-069.</p>
 */
@Tag("integration")
@Testcontainers
class KeyAuditCloudWatchAdapterIT {

    private static final String LOG_GROUP = "/eudistack/audit/wallet-ebw/test";
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
        logStreamName = "test-stream-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        logsClient = CloudWatchLogsAsyncClient.builder()
                .endpointOverride(localStack.getEndpointOverride(LocalStackContainer.Service.CLOUDWATCHLOGS))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .region(Region.of(localStack.getRegion()))
                .build();

        try {
            logsClient.createLogGroup(CreateLogGroupRequest.builder()
                    .logGroupName(LOG_GROUP)
                    .build()).join();
        } catch (Exception e) {
            if (!(e.getCause() instanceof ResourceAlreadyExistsException)) throw e;
        }
        logsClient.createLogStream(CreateLogStreamRequest.builder()
                .logGroupName(LOG_GROUP)
                .logStreamName(logStreamName)
                .build()).join();
    }

    // -------------------------------------------------------------------------
    // AC-07 — event shape: required fields present, no private key material
    // -------------------------------------------------------------------------

    @Test
    void emit_keyGenerated_publishesBatchWithCorrectFieldsAndNoPrivateKeyMaterial()
            throws Exception {
        String tenantId = "test-tenant";
        String holderId = UUID.randomUUID().toString();
        String credentialId = "cred-audit-shape";
        String jkt = "sha256-thumbprint-abc";
        String correlationId = UUID.randomUUID().toString();

        KeyAuditEvent event = KeyAuditEvent.forGeneration(
                KeyAuditEvent.KeyAuditEventType.KEY_GENERATED,
                tenantId,
                holderId,
                credentialId,
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                jkt,
                Instant.now(),
                correlationId
        );

        KeyAuditCloudWatchAdapter adapter = new KeyAuditCloudWatchAdapter(
                LOG_GROUP, objectMapper, logsClient, logStreamName);

        try {
            adapter.emit(event).block();
            adapter.triggerDrainForTest().block();

            List<OutputLogEvent> logEvents = logsClient.getLogEvents(GetLogEventsRequest.builder()
                    .logGroupName(LOG_GROUP)
                    .logStreamName(logStreamName)
                    .startFromHead(true)
                    .build()).join().events();

            assertThat(logEvents)
                    .as("at least one batch must be published to CloudWatch (AC-07)")
                    .isNotEmpty();

            String message = logEvents.get(0).message();
            @SuppressWarnings("unchecked")
            Map<String, Object> batch = objectMapper.readValue(message, Map.class);

            // Batch-level fields
            assertThat(batch).containsKey("batch_id");
            assertThat(batch).containsKey("batch_hash");
            assertThat(batch).containsKey("published_at");
            assertThat(batch.get("previous_batch_hash"))
                    .as("first batch must use zero-hash seed (ADR-062)")
                    .isEqualTo(ZERO_HASH);

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> events = (List<Map<String, Object>>) batch.get("events");
            assertThat(events).hasSize(1);

            Map<String, Object> e = events.get(0);

            // Required fields per AC-07
            assertThat(e.get("event_type")).isEqualTo("key.generated");
            assertThat(e.get("tenant_id")).isEqualTo(tenantId);
            assertThat(e.get("holder_id")).isEqualTo(holderId);
            assertThat(e.get("credential_id")).isEqualTo(credentialId);
            assertThat(e.get("format")).isEqualTo("dc+sd-jwt");
            assertThat(e.get("algorithm")).isEqualTo("ES256");
            assertThat(e.get("jkt")).isEqualTo(jkt);
            assertThat(e).containsKey("timestamp");
            assertThat(e.get("correlation_id")).isEqualTo(correlationId);

            // No private key material (AC-07 security invariant)
            String rawMessage = message;
            assertThat(rawMessage)
                    .as("batch must not contain 'private_key' field (AC-07 — no key material)")
                    .doesNotContain("private_key");
            assertThat(rawMessage)
                    .as("batch must not contain 'key_bytes' field (AC-07 — no key material)")
                    .doesNotContain("key_bytes");
            assertThat(rawMessage)
                    .as("batch must not contain 'd' JWK field (AC-07 — no private JWK)")
                    .doesNotContain("\"d\"");

        } finally {
            adapter.destroy();
        }
    }

    // -------------------------------------------------------------------------
    // AC-07 — KEY_FETCHED event type also published correctly (EC-01)
    // -------------------------------------------------------------------------

    @Test
    void emit_keyFetched_publishesBatchWithFetchedEventType() throws Exception {
        KeyAuditEvent event = KeyAuditEvent.forGeneration(
                KeyAuditEvent.KeyAuditEventType.KEY_FETCHED,
                "tenant-fetch",
                UUID.randomUUID().toString(),
                "cred-fetch",
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                "jkt-fetch",
                Instant.now(),
                UUID.randomUUID().toString()
        );

        KeyAuditCloudWatchAdapter adapter = new KeyAuditCloudWatchAdapter(
                LOG_GROUP, objectMapper, logsClient, logStreamName);

        try {
            adapter.emit(event).block();
            adapter.triggerDrainForTest().block();

            List<OutputLogEvent> logEvents = logsClient.getLogEvents(GetLogEventsRequest.builder()
                    .logGroupName(LOG_GROUP)
                    .logStreamName(logStreamName)
                    .startFromHead(true)
                    .build()).join().events();

            assertThat(logEvents).isNotEmpty();
            @SuppressWarnings("unchecked")
            Map<String, Object> batch = objectMapper.readValue(logEvents.get(0).message(), Map.class);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> events = (List<Map<String, Object>>) batch.get("events");

            assertThat(events.get(0).get("event_type"))
                    .as("idempotent reuse must publish key.fetched event (EC-01)")
                    .isEqualTo("key.fetched");
        } finally {
            adapter.destroy();
        }
    }
}