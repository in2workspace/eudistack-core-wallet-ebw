package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.InvalidCommitException;
import com.eudistack.ebw.keymanager.domain.exception.OnboardingStateException;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitRequest;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitResponse;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderInitRequest;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderInitResponse;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.HybridKeyManagerTelemetryPort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * Application use case for hybrid-mode holder key enrolment.
 *
 * <h2>init — skeleton (US-02)</h2>
 * <p>Delegates salt generation to {@link PrfSaltUseCase} (implemented by US-05 /
 * EUDISTACK-537) and returns the encoded PRF salt + static KDF parameters so the Wallet
 * PWA can derive the wrap key client-side. Until US-05 is merged, calls to
 * {@link #init} will fail at runtime with a {@link OnboardingStateException} from the
 * placeholder bean.</p>
 *
 * <h2>commit — full implementation (US-02)</h2>
 * <p>Receives the AES-256-GCM-wrapped holder private key and persists exactly one handle
 * per {@code (holderId, credentialId)} composite (tenant isolation via {@code search_path}), with idempotency:
 * <ul>
 *   <li>Identical re-submit → acknowledge (AC-07).</li>
 *   <li>Different blob for the same tuple → {@link OnboardingStateException} (ES-03).</li>
 *   <li>Concurrent first-submit race → duplicate key error mapped to
 *       {@link OnboardingStateException} (handled in the R2DBC adapter).</li>
 * </ul>
 *
 * <p>Security invariants enforced here (never in the HTTP layer):
 * <ul>
 *   <li>{@code wrapped_blob} ≥ 48 bytes after base64url decode (ES-01).</li>
 *   <li>{@code iv} = 12 bytes (AES-GCM nonce) (ES-01).</li>
 *   <li>{@code tag} = 16 bytes (AES-GCM authentication tag) (ES-01).</li>
 * </ul>
 *
 * <p>{@code cnf_jwk} must not contain private key parameter {@code "d"} (AC-03) — validated
 * by the controller before invoking this use case.</p>
 *
 * <p>The {@code holder_id} is injected by the controller from the DPoP session — it is
 * NEVER read from the request body (AC-06).</p>
 *
 * <p>Spec: EUDISTACK-534 AC-01..AC-07, ES-01..ES-03; architecture.md §5.1, §6.1.</p>
 */
public class EnrollHolderUseCase {

    private static final Logger log = LoggerFactory.getLogger(EnrollHolderUseCase.class);

    private static final String KDF_PARAMS =
            "{\"algo\":\"HKDF-SHA-256\",\"info\":\"hybrid-wrap-v1\"}";
    private static final String SIGNING_PUBKEY_ENVELOPE_FORMAT = "SD-JWT";

    private final PrfSaltUseCase prfSaltUseCase;
    private final WrappedKeyHandleRepository wrappedKeyHandleRepository;
    private final HybridKeyManagerTelemetryPort telemetry;
    private final KeyAuditPort auditPort;
    private final Tracer tracer;

    public EnrollHolderUseCase(PrfSaltUseCase prfSaltUseCase,
                                WrappedKeyHandleRepository wrappedKeyHandleRepository,
                                HybridKeyManagerTelemetryPort telemetry,
                                KeyAuditPort auditPort,
                                Tracer tracer) {
        this.prfSaltUseCase = prfSaltUseCase;
        this.wrappedKeyHandleRepository = wrappedKeyHandleRepository;
        this.telemetry = telemetry;
        this.auditPort = auditPort;
        this.tracer = tracer;
    }

    /**
     * Returns the current OTEL trace id as the audit correlation id (EUDISTACK-540 FR-16),
     * so the same operation can be located across logs, traces, and the audit trail.
     * Falls back to a random UUID when no span is active (e.g. unit tests without tracing).
     */
    private String currentCorrelationId() {
        Span span = tracer.currentSpan();
        return span != null ? span.context().traceId() : UUID.randomUUID().toString();
    }

    /**
     * Initialises the hybrid onboarding flow.
     *
     * <p>Generates (or retrieves) the PRF salt via {@link PrfSaltUseCase} and returns it
     * together with static KDF parameters. Implementation of PRF salt persistence lives
     * in US-05 (EUDISTACK-537).</p>
     *
     * @param tenantId  tenant extracted from Reactor context by the controller
     * @param holderId  holder UUID from DPoP session (not from the request body)
     * @param req       validated init request
     * @return init response with base64url PRF salt and KDF parameters
     */
    public Mono<EnrollHolderInitResponse> init(String tenantId, String holderId,
                                                EnrollHolderInitRequest req) {
        telemetry.recordPrfAttempt(tenantId);
        return prfSaltUseCase.getOrCreatePrfSalt(tenantId, holderId, req.credentialId())
                .doOnNext(ignored -> telemetry.recordPrfPass(tenantId))
                .map(saltBytes -> {
                    String prfSaltEncoded = Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(saltBytes);
                    return new EnrollHolderInitResponse(
                            prfSaltEncoded, KDF_PARAMS, SIGNING_PUBKEY_ENVELOPE_FORMAT);
                });
    }

    /**
     * Commits the wrapped holder key produced by the Wallet PWA.
     *
     * <p>Validates, decodes, checks idempotency, and persists exactly one handle per
     * {@code (holderId, credentialId)} composite (tenant isolation via {@code search_path}).
     * See class javadoc for the full invariant set.</p>
     *
     * @param tenantId  tenant domain extracted from Reactor context by the controller
     * @param holderId  holder UUID from DPoP session (not from the request body)
     * @param req       validated commit request
     * @return commit response confirming the enrolled credential ID (201 new / 200 replay)
     * @throws InvalidCommitException   if any byte-length invariant fails or {@code cnf_jwk}
     *                                  contains a private key parameter
     * @throws OnboardingStateException if a different blob already exists (409) or a
     *                                  concurrent insert races to the same composite PK
     */
    public Mono<EnrollHolderCommitResponse> commit(String tenantId, String holderId,
                                                    EnrollHolderCommitRequest req) {
        return Mono.defer(() -> {
            // Step 1 — decode and validate byte lengths
            byte[] wrappedBlobBytes;
            byte[] ivBytes;
            byte[] tagBytes;
            try {
                Base64.Decoder urlDecoder = Base64.getUrlDecoder();
                wrappedBlobBytes = urlDecoder.decode(req.wrappedBlob());
                ivBytes           = urlDecoder.decode(req.iv());
                tagBytes          = urlDecoder.decode(req.tag());
            } catch (IllegalArgumentException e) {
                return Mono.error(new InvalidCommitException(
                        "base64url decode failed: " + e.getMessage()));
            }
            if (wrappedBlobBytes.length < 48) {
                return Mono.error(new InvalidCommitException(
                        "wrapped_blob must decode to at least 48 bytes"));
            }
            if (ivBytes.length != 12) {
                return Mono.error(new InvalidCommitException(
                        "iv must decode to exactly 12 bytes (AES-GCM nonce)"));
            }
            if (tagBytes.length != 16) {
                return Mono.error(new InvalidCommitException(
                        "tag must decode to exactly 16 bytes (AES-GCM authentication tag)"));
            }

            final byte[] blob = wrappedBlobBytes;
            final byte[] iv   = ivBytes;
            final byte[] tag  = tagBytes;

            // Step 2 — idempotency check
            return wrappedKeyHandleRepository.findBy(holderId, req.credentialId())
                    .flatMap(existingOpt -> {
                        if (existingOpt.isPresent()) {
                            WrappedKeyHandle existing = existingOpt.get();
                            boolean sameBlob = Arrays.equals(existing.wrappedBlob(), blob)
                                    && Arrays.equals(existing.iv(), iv)
                                    && Arrays.equals(existing.tag(), tag);
                            if (sameBlob) {
                                // Identical re-submit → idempotent ACK (AC-07), returns 200
                                return Mono.just(new EnrollHolderCommitResponse(req.credentialId(), true));
                            }
                            // Different blob → conflict (ES-03)
                            return Mono.error(new OnboardingStateException(
                                    "A wrapped key handle with different content already exists " +
                                    "for this credential (idempotency_replay)"));
                        }

                        // Step 3 — first-time commit: persist and return 201
                        WrappedKeyHandle handle = new WrappedKeyHandle(
                                holderId, req.credentialId(),
                                blob, iv, tag,
                                req.kdfAlgo(), req.kdfVersion(),
                                req.cnfJwk(), Instant.now(), null);

                        KeyAuditEvent event = KeyAuditEvent.forWrap(
                                tenantId, holderId, req.credentialId(),
                                Instant.now(), currentCorrelationId());

                        return wrappedKeyHandleRepository.insert(handle)
                                .then(auditPort.emit(event)
                                        .onErrorResume(e -> {
                                            log.warn("keymanager.hybrid.wrap_audit_failed credentialId={}: {}",
                                                    req.credentialId(), e.getMessage());
                                            return Mono.empty();
                                        }))
                                .thenReturn(new EnrollHolderCommitResponse(req.credentialId(), false));
                    });
        });
    }

    /**
     * Records the holder's acceptance of the multi-device constraint in the audit log.
     *
     * <p>Errors are propagated to the caller: for pure-audit endpoints where the only
     * purpose is recording, an audit failure must surface as a server error so the client
     * knows the consent was not persisted (US-06 AC-02).</p>
     *
     * @param tenantId tenant domain extracted from Reactor context
     * @param holderId holder UUID from DPoP session
     * @return Mono that completes when the audit event is queued, or errors on failure
     */
    public Mono<Void> recordConsent(String tenantId, String holderId) {
        return Mono.defer(() -> {
            KeyAuditEvent event = KeyAuditEvent.forConsent(
                    tenantId, holderId, Instant.now(), currentCorrelationId());
            return auditPort.emit(event);
        });
    }

    /**
     * Records that hybrid onboarding was blocked because the holder's device does not
     * support Passkey PRF (US-08, AC-01).
     *
     * <p>Errors are propagated: the endpoint exists solely to audit this event, so a
     * CloudWatch failure must surface as a server error.</p>
     *
     * @param tenantId tenant domain extracted from Reactor context
     * @param holderId holder UUID from DPoP session
     * @return Mono that completes when the audit event is queued, or errors on failure
     */
    public Mono<Void> recordPrfUnsupported(String tenantId, String holderId) {
        return Mono.defer(() -> {
            KeyAuditEvent event = KeyAuditEvent.forPrfUnsupported(
                    tenantId, holderId, Instant.now(), currentCorrelationId());
            return auditPort.emit(event);
        });
    }

}