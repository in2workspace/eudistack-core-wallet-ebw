package com.eudistack.ebw.keymanager.infrastructure.adapter.audit;

import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.model.SignaturePurpose;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.test.StepVerifier;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsAsyncClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.CloudWatchLogsException;
import software.amazon.awssdk.services.cloudwatchlogs.model.CreateLogStreamRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.CreateLogStreamResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutRetentionPolicyRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutRetentionPolicyResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.ResourceAlreadyExistsException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link KeyAuditCloudWatchAdapter} with a mocked {@link CloudWatchLogsAsyncClient}: log stream
 * bootstrap, canonical batch payload, the SHA-256 hash chain (ADR-062) and shutdown flush. The end-to-end publish
 * against LocalStack is covered by {@code KeyAuditCloudWatchAdapterIT}.
 */
class KeyAuditCloudWatchAdapterTest {

    private static final String GROUP = "/eudistack/ebw/key-audit";
    private static final String STREAM = "key-manager-test";
    private static final String ZERO_HASH = "0".repeat(64);
    private static final Instant TIMESTAMP = Instant.parse("2026-06-01T10:00:00Z");

    private final ObjectMapper objectMapper = new ObjectMapper();
    private CloudWatchLogsAsyncClient logsClient;
    private KeyAuditCloudWatchAdapter adapter;

    @BeforeEach
    void setUp() {
        logsClient = mock(CloudWatchLogsAsyncClient.class);
        when(logsClient.createLogStream(any(CreateLogStreamRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(CreateLogStreamResponse.builder().build()));
        when(logsClient.putRetentionPolicy(any(PutRetentionPolicyRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(PutRetentionPolicyResponse.builder().build()));
        when(logsClient.putLogEvents(any(PutLogEventsRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(PutLogEventsResponse.builder().build()));
    }

    @AfterEach
    void tearDown() {
        if (adapter != null) {
            adapter.destroy();
        }
    }

    @Test
    void constructor_createsTheStreamAndSetsSevenYearRetention() {
        // Act
        adapter = newAdapter();

        // Assert
        var stream = ArgumentCaptor.forClass(CreateLogStreamRequest.class);
        verify(logsClient).createLogStream(stream.capture());
        assertThat(stream.getValue().logGroupName()).isEqualTo(GROUP);
        assertThat(stream.getValue().logStreamName()).isEqualTo(STREAM);
        var retention = ArgumentCaptor.forClass(PutRetentionPolicyRequest.class);
        verify(logsClient).putRetentionPolicy(retention.capture());
        assertThat(retention.getValue().retentionInDays()).isEqualTo(2555);
    }

    @Test
    void constructor_streamAlreadyExists_stillAppliesRetention() {
        // Arrange
        when(logsClient.createLogStream(any(CreateLogStreamRequest.class)))
                .thenReturn(CompletableFuture.failedFuture(
                        ResourceAlreadyExistsException.builder().message("exists").build()));

        // Act
        adapter = newAdapter();

        // Assert
        verify(logsClient).putRetentionPolicy(any(PutRetentionPolicyRequest.class));
    }

    @Test
    void constructor_awsUnavailable_doesNotFailStartup() {
        // Arrange
        when(logsClient.createLogStream(any(CreateLogStreamRequest.class)))
                .thenReturn(CompletableFuture.failedFuture(SdkClientException.create("no credentials")));
        when(logsClient.putRetentionPolicy(any(PutRetentionPolicyRequest.class)))
                .thenReturn(CompletableFuture.failedFuture(SdkClientException.create("no credentials")));

        // Act
        adapter = newAdapter();

        // Assert
        verify(logsClient).putRetentionPolicy(any(PutRetentionPolicyRequest.class));
    }

    @Test
    void drain_signingEvent_publishesCanonicalBatchWhoseHashMatchesThePayload() throws Exception {
        // Arrange
        adapter = newAdapter();
        adapter.emit(signingEvent());

        // Act
        StepVerifier.create(adapter.triggerDrainForTest()).verifyComplete();

        // Assert
        var published = publishedMessages(1).get(0);
        assertThat(published.get("previous_batch_hash")).isEqualTo(ZERO_HASH);
        assertThat(published.get("batch_hash")).isEqualTo(sha256OfCanonical(published));
        var events = eventsOf(published);
        assertThat(events).hasSize(1);
        assertThat(events.get(0))
                .containsEntry("event_type", "key.signed")
                .containsEntry("event_version", "1")
                .containsEntry("algorithm", "ES256")
                .containsEntry("format", "dc+sd-jwt")
                .containsEntry("credential_id", "cred-1")
                .containsEntry("jkt", "jkt-1")
                .containsEntry("signing_type", "KB_JWT")
                .containsEntry("purpose", "PRESENTATION")
                .containsEntry("consumer_origin", "OID4VP_RESPONDER")
                .containsEntry("reason", "ok")
                .containsEntry("key_id", "key-1")
                .containsEntry("batch_id", published.get("batch_id"))
                .containsEntry("timestamp", TIMESTAMP.toString());
    }

    @Test
    void drain_eventWithoutKeyContext_omitsTheOptionalFields() throws Exception {
        // Arrange
        adapter = newAdapter();
        adapter.emit(KeyAuditEvent.forConsent("sandbox", "holder-1", TIMESTAMP, "corr-1"));

        // Act
        StepVerifier.create(adapter.triggerDrainForTest()).verifyComplete();

        // Assert
        var event = eventsOf(publishedMessages(1).get(0)).get(0);
        assertThat(event).containsEntry("event_type", "constraint.accepted")
                .doesNotContainKeys("algorithm", "credential_id", "format", "jkt", "signing_type", "purpose",
                        "consumer_origin", "reason", "key_id");
    }

    @Test
    void drain_consecutiveBatches_chainEachHashToThePreviousOne() throws Exception {
        // Arrange
        adapter = newAdapter();

        // Act
        adapter.emit(signingEvent());
        StepVerifier.create(adapter.triggerDrainForTest()).verifyComplete();
        adapter.emit(signingEvent());
        StepVerifier.create(adapter.triggerDrainForTest()).verifyComplete();

        // Assert
        var messages = publishedMessages(2);
        assertThat(messages.get(1).get("previous_batch_hash")).isEqualTo(messages.get(0).get("batch_hash"));
    }

    @Test
    void drain_publishFails_swallowsTheErrorAndKeepsThePreviousHash() throws Exception {
        // Arrange
        adapter = newAdapter();
        when(logsClient.putLogEvents(any(PutLogEventsRequest.class)))
                .thenReturn(CompletableFuture.failedFuture(CloudWatchLogsException.builder().message("throttled").build()))
                .thenReturn(CompletableFuture.completedFuture(PutLogEventsResponse.builder().build()));

        // Act
        adapter.emit(signingEvent());
        StepVerifier.create(adapter.triggerDrainForTest()).verifyComplete();
        adapter.emit(signingEvent());
        StepVerifier.create(adapter.triggerDrainForTest()).verifyComplete();

        // Assert — the failed batch did not advance the chain
        var messages = publishedMessages(2);
        assertThat(messages.get(1).get("previous_batch_hash")).isEqualTo(ZERO_HASH);
    }

    @Test
    void drain_emptyBuffer_publishesNothing() {
        // Arrange
        adapter = newAdapter();

        // Act
        StepVerifier.create(adapter.triggerDrainForTest()).verifyComplete();

        // Assert
        verify(logsClient, never()).putLogEvents(any(PutLogEventsRequest.class));
    }

    @Test
    void destroy_pendingEvents_flushesThemAndClosesTheClient() throws Exception {
        // Arrange
        var toDestroy = newAdapter();
        toDestroy.emit(signingEvent());
        toDestroy.emit(KeyAuditEvent.forWrap("sandbox", "holder-1", "cred-1", TIMESTAMP, "corr-2"));

        // Act
        toDestroy.destroy();

        // Assert
        assertThat(eventsOf(publishedMessages(1).get(0))).hasSize(2);
        verify(logsClient).close();
    }

    @Test
    void destroy_flushFails_stillClosesTheClient() {
        // Arrange
        when(logsClient.putLogEvents(any(PutLogEventsRequest.class)))
                .thenReturn(CompletableFuture.failedFuture(CloudWatchLogsException.builder().message("down").build()));
        var toDestroy = newAdapter();
        toDestroy.emit(signingEvent());

        // Act
        toDestroy.destroy();

        // Assert
        verify(logsClient).close();
    }

    @Test
    void destroy_noPendingEvents_onlyClosesTheClient() {
        // Arrange
        var toDestroy = newAdapter();

        // Act
        toDestroy.destroy();

        // Assert
        verify(logsClient, never()).putLogEvents(any(PutLogEventsRequest.class));
        verify(logsClient).close();
    }

    private KeyAuditCloudWatchAdapter newAdapter() {
        return new KeyAuditCloudWatchAdapter(GROUP, objectMapper, logsClient, STREAM);
    }

    private static KeyAuditEvent signingEvent() {
        return KeyAuditEvent.forSigning(KeyAuditEventType.KEY_SIGNED, "sandbox", "holder-1", "cred-1",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256, "jkt-1", TIMESTAMP, "corr-1",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.OID4VP_RESPONDER, "ok", "key-1");
    }

    private List<Map<String, Object>> publishedMessages(int expected) throws Exception {
        var requests = ArgumentCaptor.forClass(PutLogEventsRequest.class);
        verify(logsClient, times(expected)).putLogEvents(requests.capture());
        var messages = new java.util.ArrayList<Map<String, Object>>();
        for (var request : requests.getAllValues()) {
            assertThat(request.logGroupName()).isEqualTo(GROUP);
            assertThat(request.logStreamName()).isEqualTo(STREAM);
            messages.add(objectMapper.readValue(request.logEvents().get(0).message(), new TypeReference<>() { }));
        }
        return messages;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> eventsOf(Map<String, Object> message) {
        return (List<Map<String, Object>>) message.get("events");
    }

    private String sha256OfCanonical(Map<String, Object> published) throws Exception {
        var canonical = new TreeMap<>(published);
        canonical.remove("batch_hash");
        var digest = MessageDigest.getInstance("SHA-256")
                .digest(objectMapper.writeValueAsString(canonical).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }
}
