package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.spi.HolderKeyMaterialPort;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
public class DeleteCredentialWorkflow {

    private static final Logger log = LoggerFactory.getLogger(DeleteCredentialWorkflow.class);

    private final WalletCredentialRepository credentialRepository;
    private final CredentialService credentialService;
    private final AuditService auditService;
    private final PasskeyCustodyPolicy custodyPolicy;
    private final HolderKeyMaterialPort holderKeyMaterial;
    private final TransactionRunner transactionRunner;

    public DeleteCredentialWorkflow(WalletCredentialRepository credentialRepository,
                                     CredentialService credentialService,
                                     AuditService auditService,
                                     PasskeyCustodyPolicy custodyPolicy,
                                     HolderKeyMaterialPort holderKeyMaterial,
                                     TransactionRunner transactionRunner) {
        this.credentialRepository = credentialRepository;
        this.credentialService = credentialService;
        this.auditService = auditService;
        this.custodyPolicy = custodyPolicy;
        this.holderKeyMaterial = holderKeyMaterial;
        this.transactionRunner = transactionRunner;
    }

    /**
     * Deletes the attestation and its key material in one transaction (EUD-11 FR-10, FR-16). With passkey
     * custody, an attestation of another passkey is answered as not found (FR-14).
     */
    public Mono<Void> deleteCredential(UUID userId, UUID sessionPasskeyId, UUID credentialId) {
        return credentialRepository.findByIdAndUserId(credentialId, userId)
                .flatMap(credential -> custodyPolicy.visibleToSession(credential, sessionPasskeyId))
                .switchIfEmpty(Mono.error(new CredentialNotFoundException()))
                .flatMap(credential -> {
                    var entityHash = credentialService.computeAuditHash(credential.getCredentialRaw());

                    // Audited once the deletion has committed, so a rolled-back deletion leaves no DELETED entry.
                    return transactionRunner.inTransaction(Mono.defer(() ->
                                    holderKeyMaterial.delete(credential)
                                            .then(Mono.defer(() -> credentialRepository.deleteById(credentialId)))))
                            .then(Mono.defer(() -> auditService.record("credential", credentialId, "DELETED", userId,
                                    Map.of("entity_hash", "sha256:" + entityHash,
                                            "credential_type", credential.getCredentialType(),
                                            "issuer", credential.getIssuer(),
                                            "format", credential.getFormat().getValue(),
                                            "previous_status", credential.getStatus().name()))));
                })
                .doOnSuccess(v -> log.info("Credential deleted: id={}, userId={}", credentialId, userId))
                .doOnError(e -> log.error("Failed to delete credential: id={}, userId={}, error={}", credentialId, userId, e.getMessage()));
    }
}
