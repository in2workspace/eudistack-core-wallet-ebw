package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.KeyAccessDeniedException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import io.r2dbc.spi.R2dbcNonTransientResourceException;
import io.r2dbc.spi.R2dbcTimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

/**
 * Application use case: signs a payload on behalf of the holder using the stored key.
 *
 * <p>Flow per AD-407-1 (path without KMS — TDE-only per ADR-099):
 * <ol>
 *   <li>Validate tenant profile — must be {@code (SERVER, DB)} (ES-03)</li>
 *   <li>Resolve holder key via {@link HolderKeyReadPort#findById(String, String, com.eudistack.ebw.keymanager.domain.model.HolderKeyId)}
 *       (SELECT with {@code WHERE tenant_id = ? AND holder_id = ? AND revoked_at IS NULL}).
 *       Includes holder isolation to prevent intra-tenant IDOR (AC-05/F1).</li>
 *   <li>Reject opaque + constant-time if key not found, revoked, or belongs to another
 *       holder (AC-06, ES-02, EC-01, AC-05/F1)</li>
 *   <li>Validate {@code signingType ↔ holder_key.format} (AC-04, EC-02) — mismatch is
 *       also routed through opaque reject (F2)</li>
 *   <li>Reconstruct private key via {@link HolderKeyFactory#fromBytes} on
 *       {@code Schedulers.boundedElastic()} (F4 — keeps JCA off the Netty event loop)
 *       → {@link PlaintextHandle}</li>
 *   <li>Select signer via {@link SignerSelector}</li>
 *   <li>Sign → zeroize handle via {@code .doFinally(...)} (AC-05, NFR-SEC-03, W1)</li>
 *   <li>Emit audit {@code KEY_SIGNED} (AC-08, FR-60)</li>
 * </ol>
 *
 * <p>Wrapped in {@code Mono.timeout(2500 ms)} (ES-05 / NFR-S-407-07).
 * Rejection paths apply {@link SignRejectionUniformDelay} to equalise timing (ADR-025).
 * All {@link PlaintextHandle} instances are closed via {@code .doFinally(...)} to guarantee
 * zeroization even on timeout or cancellation (W1).</p>
 *
 * <p>Spec: EUDISTACK-407, FR-20, FR-21, FR-22, FR-60, ADR-021, ADR-024, ADR-025, ADR-099,
 * NFR-SEC-03, NFR-PERF-01.</p>
 */
public class SignHolderKeyUseCase {

    private static final Logger log = LoggerFactory.getLogger(SignHolderKeyUseCase.class);

    static final Duration OUTER_TIMEOUT = Duration.ofMillis(2500);

    private final HolderKeyReadPort holderKeyReadPort;
    private final HolderKeyFactory holderKeyFactory;
    private final SignerSelector signerSelector;
    private final SignRejectionUniformDelay rejectionDelay;
    private final KeyAuditPort auditPort;
    private final WalletProfileQueryPort walletProfileQueryPort;

    public SignHolderKeyUseCase(HolderKeyReadPort holderKeyReadPort,
                                 HolderKeyFactory holderKeyFactory,
                                 SignerSelector signerSelector,
                                 SignRejectionUniformDelay rejectionDelay,
                                 KeyAuditPort auditPort,
                                 WalletProfileQueryPort walletProfileQueryPort) {
        this.holderKeyReadPort = holderKeyReadPort;
        this.holderKeyFactory = holderKeyFactory;
        this.signerSelector = signerSelector;
        this.rejectionDelay = rejectionDelay;
        this.auditPort = auditPort;
        this.walletProfileQueryPort = walletProfileQueryPort;
    }

    /**
     * Executes the sign use case, wrapped in a 2500 ms timeout.
     *
     * @param cmd the signing command; must not be null
     * @return a {@code Mono} emitting the signed result, or terminating with a domain exception
     */
    public Mono<SignHolderKeyResult> execute(SignHolderKeyCommand cmd) {
        return Mono.defer(() -> doExecute(cmd))
                .timeout(OUTER_TIMEOUT)
                .doOnError(throwable -> {
                    if (throwable instanceof java.util.concurrent.TimeoutException) {
                        log.warn("keymanager.sign.timeout keyId={} tenant={}", cmd.keyId(), cmd.tenantId());
                        emitAuditFireAndForget(buildTimeoutEvent(cmd));
                    }
                });
    }

    private Mono<SignHolderKeyResult> doExecute(SignHolderKeyCommand cmd) {
        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> {
                    if (profile.walletMode() != WalletMode.SERVER
                            || profile.keyManager() != KeyManager.DB) {
                        // ES-03: profile mismatch — NOT opaque (tenant config is public)
                        return Mono.error(new TenantWalletProfileUnsupportedException(cmd.tenantId()));
                    }
                    return resolveAndSign(cmd);
                })
                .onErrorResume(TenantUnknownException.class, ex ->
                        Mono.error(new TenantWalletProfileUnsupportedException(cmd.tenantId())));
    }

    private Mono<SignHolderKeyResult> resolveAndSign(SignHolderKeyCommand cmd) {
        return holderKeyReadPort.findById(cmd.tenantId(), cmd.holderId(), cmd.keyId())
                .flatMap(holderKey -> signWithKey(cmd, holderKey))
                .switchIfEmpty(opaqueReject(cmd, "KEY_NOT_FOUND"))
                // B3 (ES-04): emit SIGN_DEPENDENCY_FAILURE audit before propagating R2DBC errors
                .onErrorResume(R2dbcTimeoutException.class, ex ->
                        emitAuditFireAndForget(buildDependencyFailureEvent(cmd, "R2DBC_TIMEOUT"))
                                .then(Mono.error(ex)))
                .onErrorResume(R2dbcNonTransientResourceException.class, ex ->
                        emitAuditFireAndForget(buildDependencyFailureEvent(cmd, "R2DBC_UNAVAILABLE"))
                                .then(Mono.error(ex)));
    }

    private Mono<SignHolderKeyResult> signWithKey(SignHolderKeyCommand cmd, HolderKey holderKey) {
        // F2: Validate signingType ↔ format BEFORE loading the private key (EC-02 fast-fail).
        // Mismatch is routed through opaqueReject — consumer receives an opaque 401 + delay.
        // Internal audit event records the actual reason.
        if (!cmd.signingType().isCompatibleWith(holderKey.format())) {
            return opaqueReject(cmd, "SIGNING_TYPE_FORMAT_MISMATCH");
        }

        // F4: subscribeOn(boundedElastic) moves all JCA operations off the Netty event loop.
        // W1: doFinally guarantees PlaintextHandle.close() on all termination signals
        //     (complete, error, cancel/timeout).
        return Mono.fromCallable(() -> holderKeyFactory.fromBytes(
                        Arrays.copyOf(holderKey.privateKey(), holderKey.privateKey().length),
                        holderKey.algorithm()))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(handle -> {
                    JwsSigner signer = signerSelector.select(cmd.signingType());
                    return Mono.fromCallable(() ->
                                    signer.sign(handle, holderKey.publicJwk(), holderKey.algorithm(),
                                            cmd.signingInput()))
                            .doFinally(signal -> handle.close());
                })
                .map(jwsCompact -> new SignHolderKeyResult(
                        jwsCompact, holderKey.algorithm(), holderKey.publicJwk().jkt()))
                .flatMap(result ->
                        emitAuditFireAndForget(buildSignedEvent(cmd, holderKey, result))
                                .thenReturn(result));
    }

    /**
     * Opaque constant-time rejection path (ADR-025 + AD-407-2).
     *
     * <p>Applies a uniform delay before emitting the audit event and raising the exception.
     * This ensures that an external observer cannot distinguish "key not found" from any
     * other rejection reason based on timing.</p>
     */
    private Mono<SignHolderKeyResult> opaqueReject(SignHolderKeyCommand cmd, String reason) {
        return rejectionDelay.apply()
                .then(Mono.defer(() -> {
                    emitAuditFireAndForget(buildRejectionEvent(cmd, null, reason));
                    return Mono.error(new KeyAccessDeniedException(reason));
                }));
    }

    // --- Audit emission (fire-and-forget — failure must never fail the main flow) ---

    private Mono<Void> emitAuditFireAndForget(KeyAuditEvent event) {
        return auditPort.emit(event).onErrorResume(e -> {
            log.error("keymanager.audit.emit_failed type={} tenant={}: {}",
                    event.type(), event.tenantId(), e.getMessage());
            return Mono.empty();
        });
    }

    // --- Event builders ---

    private KeyAuditEvent buildSignedEvent(SignHolderKeyCommand cmd, HolderKey key,
                                            SignHolderKeyResult result) {
        return KeyAuditEvent.forSigning(
                KeyAuditEventType.KEY_SIGNED,
                cmd.tenantId(),
                cmd.holderId(),
                key.credentialId(),
                key.format(),
                key.algorithm(),
                result.jkt(),
                Instant.now(),
                UUID.randomUUID().toString(),
                cmd.signingType(),
                cmd.purpose(),
                cmd.origin(),
                null,
                // B2: populate keyId so auditors can correlate with the key lifecycle event
                key.id().value().toString()
        );
    }

    private KeyAuditEvent buildRejectionEvent(SignHolderKeyCommand cmd, HolderKey key, String reason) {
        // When key is null (not found), use placeholder values that contain no secret
        String credentialId = (key != null) ? key.credentialId() : "UNKNOWN";
        CredentialFormat format = (key != null) ? key.format() : CredentialFormat.SD_JWT_VC;
        KeyAlgorithm algorithm = (key != null) ? key.algorithm() : KeyAlgorithm.ES256;
        String jkt = (key != null) ? key.publicJwk().jkt() : "UNKNOWN";
        String keyIdStr = (key != null) ? key.id().value().toString() : null;

        return KeyAuditEvent.forSigning(
                KeyAuditEventType.SIGN_REJECTED,
                cmd.tenantId(),
                cmd.holderId(),
                credentialId,
                format,
                algorithm,
                jkt,
                Instant.now(),
                UUID.randomUUID().toString(),
                cmd.signingType(),
                cmd.purpose(),
                cmd.origin(),
                reason,
                keyIdStr
        );
    }

    private KeyAuditEvent buildTimeoutEvent(SignHolderKeyCommand cmd) {
        return KeyAuditEvent.forSigning(
                KeyAuditEventType.SIGN_TIMEOUT,
                cmd.tenantId(),
                cmd.holderId(),
                "UNKNOWN",
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                "UNKNOWN",
                Instant.now(),
                UUID.randomUUID().toString(),
                cmd.signingType(),
                cmd.purpose(),
                cmd.origin(),
                "TIMEOUT",
                null
        );
    }

    /**
     * B3 (ES-04): builds a {@code SIGN_DEPENDENCY_FAILURE} event when a DB/infra error
     * prevents the signing operation. The key was not resolved at this point, so {@code keyId},
     * {@code credentialId}, and {@code jkt} are placeholder values.
     */
    private KeyAuditEvent buildDependencyFailureEvent(SignHolderKeyCommand cmd, String reason) {
        return KeyAuditEvent.forSigning(
                KeyAuditEventType.SIGN_DEPENDENCY_FAILURE,
                cmd.tenantId(),
                cmd.holderId(),
                "UNKNOWN",
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                "UNKNOWN",
                Instant.now(),
                UUID.randomUUID().toString(),
                cmd.signingType(),
                cmd.purpose(),
                cmd.origin(),
                reason,
                null
        );
    }
}
