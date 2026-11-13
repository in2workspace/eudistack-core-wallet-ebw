package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.spi.HolderKeyMaterialPort;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Deletes an attestation together with its key material and audits it. Shared by the deletion the user asks
 * for and the purge of expired orphan attestations, so both leave the same trace.
 */
@Service
@RequiredArgsConstructor
public class CredentialRemover {

    private final WalletCredentialRepository credentialRepository;
    private final CredentialService credentialService;
    private final AuditService auditService;
    private final HolderKeyMaterialPort holderKeyMaterial;
    private final TransactionRunner transactionRunner;

    /**
     * Deletes the attestation and its key material and records {@code DELETED}, all in one transaction: a
     * rolled-back deletion leaves no entry, and a deletion is never left without its entry.
     *
     * @param actorId            who asked for the deletion; {@code null} when the service itself does it
     * @param extraAuditMetadata added to the audit entry, e.g. why the attestation was deleted
     */
    public Mono<Void> remove(WalletCredential credential, UUID actorId, Map<String, Object> extraAuditMetadata) {
        var entityHash = credentialService.computeAuditHash(credential.getCredentialRaw());
        var metadata = new HashMap<String, Object>(extraAuditMetadata);
        metadata.put("entity_hash", "sha256:" + entityHash);
        metadata.put("credential_type", credential.getCredentialType());
        metadata.put("issuer", credential.getIssuer());
        metadata.put("format", credential.getFormat().getValue());
        metadata.put("previous_status", credential.getStatus().name());

        return transactionRunner.inTransaction(Mono.defer(() ->
                holderKeyMaterial.delete(credential)
                        .then(Mono.defer(() -> credentialRepository.deleteById(credential.getId())))
                        .then(Mono.defer(() -> auditService.record("credential", credential.getId(), "DELETED",
                                actorId, metadata)))));
    }
}
