package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyPersistResult;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.JwsProof;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import reactor.core.publisher.Mono;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

/**
 * Application use case: generates a holder key and OID4VCI proof JWT for credential issuance.
 *
 * <p>Flow per AD-119-2:
 * <ol>
 *   <li>Negotiate algorithm (ADR-024): EdDSA &gt; ES384 &gt; ES256</li>
 *   <li>Generate key pair (JCA/BC)</li>
 *   <li>UPSERT — idempotent under concurrent first-issuance (EC-01, ADR-021)</li>
 *   <li>Sign OID4VCI proof JWT (OID4VCI §8.2) with the canonical key:
 *       <ul>
 *         <li>"created" branch: sign with the newly generated key, then zeroize</li>
 *         <li>"fetched" branch: zeroize new key, reconstruct existing key, sign, zeroize</li>
 *       </ul>
 *   </li>
 *   <li>Emit audit event — fire-and-forget; failure never fails the main flow (AD-119-3)</li>
 * </ol>
 *
 * <p>Key hygiene: every {@link PlaintextHandle} opened here is guaranteed to be closed
 * (i.e. the backing byte array is zeroed) before the returned Mono completes, whether on
 * success or on error. The zeroization is idempotent so double-close is safe.</p>
 *
 * <p>Spec: EUDISTACK-119, OID4VCI 1.0 §7/§8.2, ADR-021, ADR-024, ADR-099.</p>
 */
public class GenerateHolderKeyUseCase {

    private final AlgorithmNegotiator negotiator;
    private final HolderKeyFactory factory;
    private final HolderKeyWritePort writePort;
    private final IssuanceProofSigner signer;
    private final KeyAuditPort auditPort;

    public GenerateHolderKeyUseCase(AlgorithmNegotiator negotiator,
                                     HolderKeyFactory factory,
                                     HolderKeyWritePort writePort,
                                     IssuanceProofSigner signer,
                                     KeyAuditPort auditPort) {
        this.negotiator = negotiator;
        this.factory = factory;
        this.writePort = writePort;
        this.signer = signer;
        this.auditPort = auditPort;
    }

    public Mono<HolderKeyResult> execute(GenerateHolderKeyCommand command) {
        return Mono.defer(() -> {
            KeyAlgorithm algorithm = negotiator.negotiate(command.supportedAlgs());
            GeneratedKeyPair generated = factory.generate(algorithm);

            // rawPrivateBytes is the same array that the handle's zeroizer will clear on close
            HolderKey candidate = new HolderKey(
                    HolderKeyId.generate(),
                    command.tenantId(),
                    command.holderId(),
                    command.credentialId(),
                    command.format(),
                    algorithm,
                    generated.rawPrivateBytes(),
                    generated.publicJwk(),
                    Instant.now(),
                    null
            );

            return writePort.upsertIfAbsent(candidate)
                    .flatMap(persistResult ->
                            signAndBuild(persistResult, generated, algorithm, command))
                    // Ensure the handle is closed even if the DB write or signing fails
                    .doOnError(e -> generated.privateKeyHandle().close())
                    .flatMap(result ->
                            emitAudit(result, command, algorithm).thenReturn(result));
        });
    }

    private Mono<HolderKeyResult> signAndBuild(HolderKeyPersistResult persistResult,
                                                GeneratedKeyPair generated,
                                                KeyAlgorithm algorithm,
                                                GenerateHolderKeyCommand command) {
        if (persistResult.created()) {
            // Sign with the newly generated key; close (zeroize) in finally
            return Mono.fromCallable(() -> {
                try {
                    JwsProof proof = signer.sign(
                            generated.privateKeyHandle(),
                            persistResult.holderKey().publicJwk(),
                            algorithm,
                            command.holderId(),
                            command.issuerIdentifier(),
                            command.cNonce());
                    return new HolderKeyResult(
                            persistResult.holderKey().id(),
                            persistResult.holderKey().publicJwk(),
                            proof,
                            true);
                } finally {
                    generated.privateKeyHandle().close();
                }
            });
        }

        // Fetched branch: discard the new key immediately, sign with the canonical existing key
        generated.privateKeyHandle().close();
        HolderKey existing = persistResult.holderKey();
        // Copy to a fresh array that fromBytes() can take ownership of and zero after signing
        byte[] existingBytes = Arrays.copyOf(existing.privateKey(), existing.privateKey().length);
        PlaintextHandle<PrivateKey> fetchedHandle = factory.fromBytes(existingBytes, algorithm);

        return Mono.fromCallable(() -> {
            try {
                JwsProof proof = signer.sign(
                        fetchedHandle,
                        existing.publicJwk(),
                        algorithm,
                        command.holderId(),
                        command.issuerIdentifier(),
                        command.cNonce());
                return new HolderKeyResult(existing.id(), existing.publicJwk(), proof, false);
            } finally {
                fetchedHandle.close();
            }
        });
    }

    private Mono<Void> emitAudit(HolderKeyResult result,
                                  GenerateHolderKeyCommand command,
                                  KeyAlgorithm algorithm) {
        KeyAuditEvent event = KeyAuditEvent.forGeneration(
                result.created() ? KeyAuditEventType.KEY_GENERATED : KeyAuditEventType.KEY_FETCHED,
                command.tenantId(),
                command.holderId(),
                command.credentialId(),
                command.format(),
                algorithm,
                result.publicJwk().jkt(),
                Instant.now(),
                UUID.randomUUID().toString()
        );
        return auditPort.emit(event).onErrorResume(e -> Mono.empty());
    }
}