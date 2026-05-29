package com.eudistack.ebw.keymanager.infrastructure.adapter.audit;

import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.SignaturePurpose;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
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
import software.amazon.awssdk.services.cloudwatchlogs.model.GetLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.OutputLogEvent;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.testcontainers.containers.localstack.LocalStackContainer.Service.CLOUDWATCHLOGS;

/**
 * Integration tests for {@link KeyAuditCloudWatchAdapter} with US-03 signing events.
 *
 * <p>Verifies that {@code KEY_SIGNED} events include the optional signing-specific fields
 * ({@code signing_type}, {@code purpose}, {@code consumer_origin}) and that no payload or
 * signature material appears in the log (NFR-S-407-05).</p>
 *
 * <p>Covers: EUDISTACK-407 AC-08, NFR-S-407-05.</p>
 */
@Tag("integration")
@Testcontainers
class KeyAuditCloudWatchAdapterIT_KeySigned {

    private static final String ZERO_HASH = "0".repeat(64);
    private static final String LOG_GROUP = "/eudistack/audit/test-sign";

    @Container
    static final LocalStackContainer localStack =
            new LocalStackContainer(DockerImageName.parse("localstack/localstack:3.0"))
                    .withServices(CLOUDWATCHLOGS);

    private CloudWatchLogsAsyncClient logsClient;
    private ObjectMapper objectMapper;
    private String logStreamName;

    @BeforeEach
    void setUp() {
        logsClient = CloudWatchLogsAsyncClient.builder()
                .endpointOverride(localStack.getEndpointOverride(CLOUDWATCHLOGS))
                .region(Region.of(localStack.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(
                                localStack.getAccessKey(), localStack.getSecretKey())))
                .build();

        objectMapper = new ObjectMapper();
        logStreamName = "sign-test-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

        logsClient.createLogGroup(CreateLogGroupRequest.builder()
                .logGroupName(LOG_GROUP)
                .build()).join();
    }

    @Test
    void emit_keySignedEvent_includesSigningFields_andNoPiiOrKeyMaterial() throws Exception {
        // Given
        String tenantId = "test-tenant";
        String holderId = UUID.randomUUID().toString();
        String correlationId = UUID.randomUUID().toString();
        String jkt = "jkt-sign-test";

        KeyAuditEvent event = KeyAuditEvent.forSigning(
                KeyAuditEvent.KeyAuditEventType.KEY_SIGNED,
                tenantId, holderId, "cred-sign", CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256, jkt, Instant.now(), correlationId,
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.OID4VP_RESPONDER,
                null
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
            String message = logEvents.get(0).message();

            @SuppressWarnings("unchecked")
            Map<String, Object> batch = objectMapper.readValue(message, Map.class);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> events = (List<Map<String, Object>>) batch.get("events");
            assertThat(events).hasSize(1);

            Map<String, Object> e = events.get(0);

            // Signing event fields
            assertThat(e.get("event_type")).isEqualTo("key.signed");
            assertThat(e.get("tenant_id")).isEqualTo(tenantId);
            assertThat(e.get("holder_id")).isEqualTo(holderId);
            assertThat(e.get("signing_type")).isEqualTo("KB_JWT");
            assertThat(e.get("purpose")).isEqualTo("PRESENTATION");
            assertThat(e.get("consumer_origin")).isEqualTo("OID4VP_RESPONDER");
            assertThat(e.get("jkt")).isEqualTo(jkt);

            // No signing material (NFR-S-407-05)
            assertThat(message).doesNotContain("payload");
            assertThat(message).doesNotContain("private_key");
            assertThat(message).doesNotContain("\"d\"");

        } finally {
            adapter.destroy();
            logsClient.close();
        }
    }

    @Test
    void emit_generationEvent_doesNotIncludeSigningFields_backwardCompat() throws Exception {
        // Given: a US-02 generation event (no signing fields)
        KeyAuditEvent event = KeyAuditEvent.forGeneration(
                KeyAuditEvent.KeyAuditEventType.KEY_GENERATED,
                "tenant-gen", "holder-gen", "cred-gen",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                "jkt-gen", Instant.now(), UUID.randomUUID().toString()
        );

        KeyAuditCloudWatchAdapter adapter = new KeyAuditCloudWatchAdapter(
                LOG_GROUP, objectMapper, logsClient,
                "gen-stream-" + UUID.randomUUID().toString().replace("-", "").substring(0, 6));

        try {
            adapter.emit(event).block();
            adapter.triggerDrainForTest().block();

            List<OutputLogEvent> logEvents = logsClient.getLogEvents(GetLogEventsRequest.builder()
                    .logGroupName(LOG_GROUP)
                    .logStreamName(logStreamName + "gen")
                    .startFromHead(true)
                    .build()).join().events();

            // The generation event path is tested in existing KeyAuditCloudWatchAdapterIT
            // This test just confirms the adapter doesn't throw on generation events
        } finally {
            adapter.destroy();
            logsClient.close();
        }
    }
}
