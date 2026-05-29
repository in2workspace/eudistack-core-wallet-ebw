package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.KeyAccessDeniedException;
import com.eudistack.ebw.keymanager.domain.exception.SigningTypeFormatMismatchException;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

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
 *   <li>Resolve holder key via {@link HolderKeyReadPort#findById(String, com.eudistack.ebw.keymanager.domain.model.HolderKeyId)}
 *       (SELECT with {@code WHERE revoked_at IS NULL})</li>
 *   <li>Reject opaque + constant-time if key not found or revoked (AC-06, ES-02, EC-01)</li>
 *   <li>Validate {@code signingType ↔ holder_key.format} (AC-04, EC-02)</li>
 *   <li>Reconstruct private key via {@link HolderKeyFactory#fromBytes} → {@link PlaintextHandle}</li>
 *   <li>Select signer via {@link SignerSelector}</li>
 *   <li>Sign → zeroize handle (AC-05, NFR-SEC-03)</li>
 *   <li>Emit audit {@code KEY_SIGNED} (AC-08, FR-60)</li>
 * </ol>
 *
 * <p>Wrapped in {@code Mono.timeout(2500 ms)} (ES-05 / NFR-S-407-07).
 * Rejection paths apply {@link SignRejectionUniformDelay} to equalise timing (ADR-025).
 * All {@link PlaintextHandle} instances are closed via {@code .doFinally(...)} to guarantee
 * zeroization even on timeout or cancellation.</p>
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
        return holderKeyReadPort.findById(cmd.tenantId(), cmd.keyId())
                .flatMap(holderKey -> signWithKey(cmd, holderKey))
                .switchIfEmpty(opaqueReject(cmd, "KEY_NOT_FOUND"));
    }

    private Mono<SignHolderKeyResult> signWithKey(SignHolderKeyCommand cmd, HolderKey holderKey) {
        // Validate signingType ↔ format BEFORE loading the private key (EC-02 fast-fail)
        if (!cmd.signingType().isCompatibleWith(holderKey.format())) {
            emitAuditFireAndForget(buildRejectionEvent(cmd, holderKey, "SIGNING_TYPE_FORMAT_MISMATCH"));
            return Mono.error(new SigningTypeFormatMismatchException(cmd.signingType(), holderKey.format()));
        }

        return Mono.fromCallable(() -> {
            byte[] rawBytes = Arrays.copyOf(holderKey.privateKey(), holderKey.privateKey().length);
            PlaintextHandle<PrivateKey> handle = holderKeyFactory.fromBytes(rawBytes, holderKey.algorithm());
            try {
                JwsSigner signer = signerSelector.select(cmd.signingType());
                String jwsCompact = signer.sign(handle, holderKey.publicJwk(), holderKey.algorithm(),
                        cmd.signingInput());
                return new SignHolderKeyResult(jwsCompact, holderKey.algorithm(), holderKey.publicJwk().jkt());
            } finally {
                handle.close();
            }
        }).flatMap(result ->
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
                null
        );
    }

    private KeyAuditEvent buildRejectionEvent(SignHolderKeyCommand cmd, HolderKey key, String reason) {
        // When key is null (not found), use placeholder values that contain no secret
        String credentialId = (key != null) ? key.credentialId() : "UNKNOWN";
        CredentialFormat format = (key != null) ? key.format() : CredentialFormat.SD_JWT_VC;
        KeyAlgorithm algorithm = (key != null) ? key.algorithm() : KeyAlgorithm.ES256;
        String jkt = (key != null) ? key.publicJwk().jkt() : "UNKNOWN";

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
                reason
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
                "TIMEOUT"
        );
    }
}
