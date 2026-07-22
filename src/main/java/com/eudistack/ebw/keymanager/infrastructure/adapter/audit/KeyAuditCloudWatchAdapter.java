package com.eudistack.ebw.keymanager.infrastructure.adapter.audit;

import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsAsyncClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.CloudWatchLogsException;
import software.amazon.awssdk.services.cloudwatchlogs.model.CreateLogStreamRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutRetentionPolicyRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.ResourceAlreadyExistsException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Publishes key lifecycle audit events to AWS CloudWatch Logs (Dominio D2 — ADR-069)
 * with a SHA-256 hash chain for integrity verification (ADR-062, no-KMS variant).
 *
 * <p><b>Protocol:</b>
 * <ol>
 *   <li>Events are offered to an in-memory bounded queue (capacity {@value BUFFER_CAPACITY}).
 *       {@link #emit} returns immediately — the hot path is never blocked.</li>
 *   <li>A periodic drain loop (every {@value DRAIN_INTERVAL_SECONDS} s on
 *       {@code boundedElastic}) drains up to {@value MAX_BATCH_SIZE} events at a time.</li>
 *   <li>Each batch produces a canonical JSON payload (keys sorted lexicographically) that
 *       includes {@code batch_id}, the serialized events, {@code previous_batch_hash}, and
 *       {@code published_at}.</li>
 *   <li>{@code batch_hash = SHA-256(UTF-8 bytes of canonical JSON)} links this batch to the
 *       next one. The first batch per instance uses {@code "0".repeat(64)} as the seed.</li>
 *   <li>The batch payload + {@code batch_hash} are published as a single CloudWatch Logs
 *       event. Each event entry in the batch carries {@code batch_id} so an auditor can
 *       locate the batch that covers a given event.</li>
 * </ol>
 *
 * <p><b>Verification:</b> An external auditor can reconstruct the canonical JSON
 * (fields: {@code batch_id}, {@code events}, {@code previous_batch_hash}, {@code published_at},
 * sorted by key), compute SHA-256, and compare with {@code batch_hash}. A missing batch
 * breaks the hash chain. No private key is ever present in the payload (NFR-S-119-04).
 *
 * <p>Buffer overflow (queue at capacity) drops the event and increments a warn log counter.
 * Clean shutdown flushes remaining events synchronously (max 10 s).</p>
 *
 * <p>Spec: ADR-062 (hash chain, no-KMS variant), ADR-069 (Dominio D2), AC-07,
 * NFR-S-119-03 (100% coverage {@code key.generated}).</p>
 */
public class KeyAuditCloudWatchAdapter implements KeyAuditPort, DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(KeyAuditCloudWatchAdapter.class);

    static final int MAX_BATCH_SIZE = 200;
    static final int DRAIN_INTERVAL_SECONDS = 5;
    static final int BUFFER_CAPACITY = 10_000;
    private static final String ZERO_HASH = "0".repeat(64);

    private final CloudWatchLogsAsyncClient logsClient;
    private final ObjectMapper objectMapper;
    private final String logGroupName;
    private final String logStreamName;

    private final LinkedBlockingQueue<KeyAuditEvent> buffer = new LinkedBlockingQueue<>(BUFFER_CAPACITY);
    private final AtomicReference<String> previousBatchHash = new AtomicReference<>(ZERO_HASH);
    private final Disposable drainSubscription;

    /**
     * Production constructor — creates the AWS client, log stream, and starts the drain loop.
     */
    public KeyAuditCloudWatchAdapter(String logGroupName, ObjectMapper objectMapper) {
        this(
                logGroupName,
                objectMapper,
                CloudWatchLogsAsyncClient.create(),
                "key-manager-" + LocalDate.now() + "-"
                        + UUID.randomUUID().toString().replace("-", "").substring(0, 8)
        );
    }

    /**
     * Package-private constructor for testing — accepts injected clients and a fixed stream name.
     * Does NOT create the log stream (the test controls that).
     */
    KeyAuditCloudWatchAdapter(String logGroupName,
                               ObjectMapper objectMapper,
                               CloudWatchLogsAsyncClient logsClient,
                               String logStreamName) {
        this.logGroupName = logGroupName;
        this.objectMapper = objectMapper;
        this.logsClient = logsClient;
        this.logStreamName = logStreamName;
        ensureLogStream();
        this.drainSubscription = Flux
                .interval(Duration.ofSeconds(DRAIN_INTERVAL_SECONDS), Schedulers.boundedElastic())
                .concatMap(tick -> drainBatch())
                .subscribe(
                        n -> { /* drain completed */ },
                        e -> log.error("Audit drain loop terminated unexpectedly — events will accumulate", e)
                );
    }

    @Override
    public Mono<Void> emit(KeyAuditEvent event) {
        if (!buffer.offer(event)) {
            log.warn("keymanager.audit.buffer_overflow type={} tenant={}",
                    event.type(), event.tenantId());
        }
        return Mono.empty();
    }

    @Override
    public void destroy() {
        drainSubscription.dispose();
        flushRemaining();
        logsClient.close();
    }

    // --- package-private for testing ---

    Mono<Void> triggerDrainForTest() {
        return drainBatch();
    }

    // --- internal ---

    private void ensureLogStream() {
        try {
            joinAndRethrowSdkException(logsClient.createLogStream(CreateLogStreamRequest.builder()
                    .logGroupName(logGroupName)
                    .logStreamName(logStreamName)
                    .build()));
            log.info("keymanager.audit.stream_created group={} stream={}", logGroupName, logStreamName);
        } catch (ResourceAlreadyExistsException e) {
            log.debug("Log stream already exists, applying retention policy");
        } catch (SdkException e) {
            log.error("keymanager.audit.stream_create_failed group={} stream={}: {}",
                    logGroupName, logStreamName, e.getMessage());
        }
        // CA-2 compliance: ensure ≥ 7-year retention on the log group (idempotent call)
        try {
            joinAndRethrowSdkException(logsClient.putRetentionPolicy(PutRetentionPolicyRequest.builder()
                    .logGroupName(logGroupName)
                    .retentionInDays(2555)
                    .build()));
            log.info("keymanager.audit.retention_set group={} days=2555", logGroupName);
        } catch (SdkException e) {
            log.error("keymanager.audit.retention_set_failed group={}: {}", logGroupName, e.getMessage());
        }
    }

    // CompletableFuture.join() wraps SDK exceptions in CompletionException; this helper unwraps
    // RuntimeExceptions so callers can catch CloudWatchLogsException / ResourceAlreadyExistsException directly.
    private static void joinAndRethrowSdkException(CompletableFuture<?> future) {
        try {
            future.join();
        } catch (CompletionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException re) throw re;
            throw ex;
        }
    }

    private Mono<Void> drainBatch() {
        List<KeyAuditEvent> batch = new ArrayList<>(MAX_BATCH_SIZE);
        buffer.drainTo(batch, MAX_BATCH_SIZE);
        if (batch.isEmpty()) {
            return Mono.empty();
        }
        return Mono.fromCallable(() -> buildBatch(batch))
                .flatMap(this::publishBatch)
                .onErrorResume(e -> {
                    log.error("keymanager.audit.batch_publish_failed size={}: {}",
                            batch.size(), e.getMessage());
                    return Mono.empty();
                });
    }

    private BatchPayload buildBatch(List<KeyAuditEvent> events)
            throws JsonProcessingException, NoSuchAlgorithmException {
        String batchId = UUID.randomUUID().toString();
        String prevHash = previousBatchHash.get();

        List<Map<String, Object>> eventMaps = events.stream()
                .map(e -> toEventMap(e, batchId))
                .toList();

        // TreeMap guarantees lexicographically sorted keys → deterministic canonical JSON
        TreeMap<String, Object> canonical = new TreeMap<>();
        canonical.put("batch_id", batchId);
        canonical.put("events", eventMaps);
        canonical.put("previous_batch_hash", prevHash);
        canonical.put("published_at", Instant.now().toString());

        byte[] payloadBytes = objectMapper.writeValueAsBytes(canonical);
        byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(payloadBytes);
        String batchHash = HexFormat.of().formatHex(digestBytes);

        return new BatchPayload(batchId, canonical, batchHash);
    }

    private Mono<Void> publishBatch(BatchPayload batch) {
        // Add batch_hash to the published message (not part of the canonical payload that was hashed)
        TreeMap<String, Object> logPayload = new TreeMap<>(batch.canonical());
        logPayload.put("batch_hash", batch.batchHash());

        final String logJson;
        try {
            logJson = objectMapper.writeValueAsString(logPayload);
        } catch (JsonProcessingException e) {
            return Mono.error(e);
        }

        InputLogEvent logEvent = InputLogEvent.builder()
                .timestamp(Instant.now().toEpochMilli())
                .message(logJson)
                .build();

        return Mono.fromFuture(() -> logsClient.putLogEvents(PutLogEventsRequest.builder()
                        .logGroupName(logGroupName)
                        .logStreamName(logStreamName)
                        .logEvents(logEvent)
                        .build()))
                .doOnSuccess(r -> {
                    previousBatchHash.set(batch.batchHash());
                    log.debug("keymanager.audit.batch_published batch_id={} events={} batch_hash={}",
                            batch.batchId(), ((List<?>) batch.canonical().get("events")).size(),
                            batch.batchHash());
                })
                .then();
    }

    private static Map<String, Object> toEventMap(KeyAuditEvent event, String batchId) {
        // TreeMap so each event entry also has sorted keys in canonical JSON
        TreeMap<String, Object> map = new TreeMap<>();
        // algorithm/credential_id/format/jkt are each conditionally absent depending on event
        // type — e.g. all four for CONSTRAINT_ACCEPTED and ONBOARDING_BLOCKED_PRF_UNSUPPORTED
        // (no key context at all), credential_id only for WRAP_COMPLETED, and jkt only for
        // UNWRAP_FAILED when the stored cnf.jwk could not be parsed (see KeyAuditEvent).
        if (event.algorithm() != null) map.put("algorithm", event.algorithm().name());
        map.put("batch_id", batchId);
        map.put("correlation_id", event.correlationId());
        if (event.credentialId() != null) map.put("credential_id", event.credentialId());
        map.put("event_type", event.type().name().toLowerCase().replace('_', '.'));
        map.put("event_version", "1");
        if (event.format() != null) map.put("format", event.format().dbValue());
        map.put("holder_id", event.holderId());
        if (event.jkt() != null) map.put("jkt", event.jkt());
        map.put("tenant_id", event.tenantId());
        map.put("timestamp", event.timestamp().toString());

        // Optional signing-specific fields (US-03 — null for US-02 generation events)
        // NOTE: payload/signature are intentionally NEVER included (NFR-S-407-05)
        if (event.signingType() != null) {
            map.put("signing_type", event.signingType().name());
        }
        if (event.purpose() != null) {
            map.put("purpose", event.purpose().name());
        }
        if (event.consumerOrigin() != null) {
            map.put("consumer_origin", event.consumerOrigin().name());
        }
        if (event.reason() != null) {
            map.put("reason", event.reason());
        }
        // B2 (AC-08): key_id correlates the signing event with the key lifecycle record
        if (event.keyId() != null) {
            map.put("key_id", event.keyId());
        }

        return map;
    }

    private void flushRemaining() {
        List<KeyAuditEvent> remaining = new ArrayList<>();
        buffer.drainTo(remaining);
        if (remaining.isEmpty()) {
            return;
        }
        log.info("keymanager.audit.shutdown_flush events={}", remaining.size());
        try {
            BatchPayload batch = buildBatch(remaining);
            // DisposableBean#destroy() is inherently synchronous; bridge via CompletableFuture
            // rather than Mono#block() to keep the reactive chain itself non-blocking.
            publishBatch(batch).toFuture().get(10, TimeUnit.SECONDS);
        } catch (CloudWatchLogsException | JsonProcessingException | NoSuchAlgorithmException
                | ExecutionException | TimeoutException e) {
            log.error("keymanager.audit.shutdown_flush_failed events={}: {}",
                    remaining.size(), e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("keymanager.audit.shutdown_flush_interrupted events={}", remaining.size());
        }
    }

    private record BatchPayload(String batchId, Map<String, Object> canonical, String batchHash) {}
}