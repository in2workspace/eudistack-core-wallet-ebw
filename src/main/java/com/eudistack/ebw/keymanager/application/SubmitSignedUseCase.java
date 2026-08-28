package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidSignatureSubmissionException;
import com.eudistack.ebw.keymanager.domain.exception.SignatureInvalidException;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionRequest;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionResponse;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.time.Instant;

/**
 * Application use case for the hybrid (Passkey PRF) signing handshake — submit step.
 *
 * <p>Fetches the pending signing session by {@code correlation_id}, enforces holder isolation,
 * verifies the client's raw ES256 signature against {@code cnf.jwk} (Nimbus
 * {@link ECDSAVerifier}), and assembles the {@code kb+jwt}. Idempotent on replay of the same
 * {@code correlation_id}: if the session is already resolved the cached {@code kb_jwt} is
 * returned immediately without re-verifying (AC-09, EC-03).</p>
 *
 * <p>Holder isolation: the {@code holderId} stored in the {@link PreparedSign} session must
 * match the {@code holderId} from the Reactor context (DPoP-bound JWT). A mismatch signals
 * a cross-holder access attempt (AC-08) and throws
 * {@link HolderIsolationViolationException} (403) — no cryptographic material is leaked.</p>
 *
 * <p>Error paths (all propagate as reactive signals — NFR-S-536-02):
 * <ul>
 *   <li>Unknown/expired {@code correlation_id} → {@link InvalidSignatureSubmissionException} (400)</li>
 *   <li>Holder isolation mismatch → {@link HolderIsolationViolationException} (403)</li>
 *   <li>Malformed {@code signature} (not valid base64url JWS part) → {@link InvalidSignatureSubmissionException} (400)</li>
 *   <li>Cryptographic verification failure → {@link SignatureInvalidException} (400)</li>
 * </ul>
 *
 * <p>No private key material is ever loaded; only {@code cnf.jwk} (the public key) is used.
 * Error messages never reference {@code prf_salt}, wrapped-blob content, or the holder
 * private key (NFR-S-536-03).</p>
 *
 * <p>Spec: EUDISTACK-536 AC-02, AC-08, AC-09, EC-03, ES-01, ES-03, ES-04,
 * NFR-S-536-02, NFR-S-536-03; architecture.md §6.2, §8.3.</p>
 */
public class SubmitSignedUseCase {

    private static final Logger log = LoggerFactory.getLogger(SubmitSignedUseCase.class);

    private final PreparedSignStore preparedSignStore;
    private final KeyAuditPort auditPort;

    public SubmitSignedUseCase(PreparedSignStore preparedSignStore, KeyAuditPort auditPort) {
        this.preparedSignStore = preparedSignStore;
        this.auditPort = auditPort;
    }

    /**
     * Executes the submit step of the hybrid signing handshake.
     *
     * <p>Reads {@code holderId} from the Reactor context (written by the controller from the
     * DPoP JWT) and verifies it matches the session owner before touching any key material.</p>
     */
    public Mono<SubmitSignedAssertionResponse> execute(SubmitSignedAssertionRequest request) {
        return Mono.deferContextual(ctx -> {
            String holderId = ctx.get(ReactorContextKeys.HOLDER_ID);
            return preparedSignStore.getIfPresent(request.correlationId())
                    .flatMap(opt -> {
                        PreparedSign prepared = opt.orElseThrow(() ->
                                new InvalidSignatureSubmissionException(
                                        "Unknown or expired correlation_id"));

                        if (!prepared.holderId().equals(holderId)) {
                            throw new HolderIsolationViolationException(request.credentialId());
                        }

                        requireMatchingCredentialId(prepared, request);

                        if (!prepared.isPending()) {
                            return Mono.just(new SubmitSignedAssertionResponse(prepared.resolvedKbJwt()));
                        }

                        return verifyAndAssemble(prepared, request);
                    });
        });
    }

    private void requireMatchingCredentialId(PreparedSign prepared, SubmitSignedAssertionRequest request) {
        if (!prepared.credentialId().equals(request.credentialId())) {
            throw new InvalidSignatureSubmissionException(
                    "credential_id does not match the prepared session");
        }
    }

    private Mono<SubmitSignedAssertionResponse> verifyAndAssemble(PreparedSign prepared,
                                                                    SubmitSignedAssertionRequest request) {
        return Mono.fromCallable(() -> {
            String compactJws = prepared.signingInput() + "." + request.signature();
            JWSObject jwsObject;
            try {
                jwsObject = JWSObject.parse(compactJws);
            } catch (ParseException e) {
                throw new InvalidSignatureSubmissionException("Malformed signature encoding");
            }

            ECKey ecKey;
            try {
                ecKey = ECKey.parse(prepared.cnfJwk());
            } catch (ParseException e) {
                throw new InvalidSignatureSubmissionException("Stored cnf.jwk is malformed");
            }

            boolean valid;
            try {
                valid = jwsObject.verify(new ECDSAVerifier(ecKey.toPublicJWK()));
            } catch (JOSEException e) {
                throw new SignatureInvalidException("Signature verification error");
            }

            if (!valid) {
                throw new SignatureInvalidException();
            }

            String kbJwt = prepared.signingInput() + "." + request.signature();
            String jkt = ecKey.computeThumbprint().toString();
            return new VerifiedResult(kbJwt, jkt);
        }).flatMap(result -> {
            KeyAuditEvent event = KeyAuditEvent.forUnwrapSignCompleted(
                    prepared.tenantId(),
                    prepared.holderId(),
                    prepared.credentialId(),
                    prepared.format(),
                    KeyAlgorithm.ES256,
                    result.jkt(),
                    Instant.now(),
                    request.correlationId());
            return preparedSignStore
                    .markResolved(request.correlationId(), result.kbJwt())
                    .then(emitAuditBestEffort(event, "keymanager.hybrid.unwrap_sign_audit_failed"))
                    .thenReturn(new SubmitSignedAssertionResponse(result.kbJwt()));
        }).onErrorResume(e -> {
            if (e instanceof SignatureInvalidException || e instanceof InvalidSignatureSubmissionException) {
                KeyAuditEvent failEvent = KeyAuditEvent.forUnwrapFailed(
                        prepared.tenantId(),
                        prepared.holderId(),
                        prepared.credentialId(),
                        prepared.format(),
                        KeyAlgorithm.ES256,
                        tryComputeJkt(prepared.cnfJwk()),
                        Instant.now(),
                        request.correlationId(),
                        e.getMessage());
                return emitAuditBestEffort(failEvent, "keymanager.hybrid.unwrap_fail_audit_failed")
                        .then(Mono.error(e));
            }
            return Mono.error(e);
        });
    }

    /**
     * Emits an audit event as a best-effort side effect composed into the reactive chain
     * (never a detached {@code subscribe()}, which would leave the emission unmanaged and
     * error handling opaque). Audit failures are logged and swallowed — they must never fail
     * the underlying signing operation.
     */
    private Mono<Void> emitAuditBestEffort(KeyAuditEvent event, String failureLogPrefix) {
        return auditPort.emit(event)
                .onErrorResume(e -> {
                    log.warn("{}: {}", failureLogPrefix, e.getMessage());
                    return Mono.empty();
                });
    }

    /** Best-effort JWK thumbprint for audit correlation (B2, AC-08) — null if cnf.jwk cannot be parsed. */
    private String tryComputeJkt(String cnfJwk) {
        try {
            return ECKey.parse(cnfJwk).computeThumbprint().toString();
        } catch (ParseException | JOSEException e) {
            return null;
        }
    }

    private record VerifiedResult(String kbJwt, String jkt) {}
}

